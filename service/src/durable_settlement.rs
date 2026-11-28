//! Shared PostgreSQL settlement journal. SQL transitions fence replicas by ID.

use std::{fmt, time::Duration};

use async_trait::async_trait;
use kite_x402_axum::{
    settlement_ledger::{
        LedgerSummary, SettlementReconciliation, SettlementRecord, SettlementVolume,
    },
    settlement_store::{SettlementStorageError, SettlementStore},
};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, PgPool, Row,
};
use tokio::sync::watch;

use crate::chain_reconciliation::{normalized_hex, ChainRpc, ScanResult};

#[derive(Clone)]
pub(crate) struct DurableStore {
    pool: PgPool,
    rpc: ChainRpc,
}

impl fmt::Debug for DurableStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableStore").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct Attempt {
    pub(crate) id: i64,
    pub(crate) payment: SettlementReconciliation,
    pub(crate) transaction: Option<String>,
    pub(crate) state: String,
    pub(crate) timestamp_secs: i64,
    scan_from: Option<i64>,
}

const COLUMNS: &str = "id, network, asset, payer, pay_to, nonce, amount_atomic::text AS amount, \
                      state, transaction_hash, EXTRACT(EPOCH FROM updated_at)::bigint AS timestamp, scan_from";

impl Attempt {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            payment: SettlementReconciliation {
                network: row.try_get("network")?,
                asset: row.try_get("asset")?,
                payer: row.try_get("payer")?,
                pay_to: row.try_get("pay_to")?,
                nonce: row.try_get("nonce")?,
                amount_atomic: row.try_get("amount")?,
            },
            transaction: row.try_get("transaction_hash")?,
            state: row.try_get("state")?,
            timestamp_secs: row.try_get("timestamp")?,
            scan_from: row.try_get("scan_from")?,
        })
    }
}

impl DurableStore {
    pub(crate) async fn connect(url: &str, rpc: ChainRpc) -> Result<Self, sqlx::Error> {
        let options = url
            .parse::<PgConnectOptions>()?
            .options([("statement_timeout", "5000"), ("synchronous_commit", "on")])
            .log_statements(tracing::log::LevelFilter::Off)
            .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_secs(1));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await?;
        let mut tx = pool.begin().await?;
        // Serialize schema initialization across replicas. Also bound waits for
        // DDL so an unavailable database cannot hang startup indefinitely.
        sqlx::query("SET LOCAL statement_timeout = '10s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(1602490402)")
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(include_str!("../sql/settlements.sql"))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Self { pool, rpc })
    }

    pub(crate) async fn recent(&self, limit: i64) -> Result<Vec<Attempt>, sqlx::Error> {
        let sql = format!("SELECT {COLUMNS} FROM kite_x402_settlement_v1 WHERE state <> 'verifying' ORDER BY updated_at DESC, id DESC LIMIT $1");
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await?;
        rows.iter().map(Attempt::from_row).collect()
    }

    pub(crate) async fn by_transaction(
        &self,
        network: &str,
        tx: &str,
    ) -> Result<Option<Attempt>, sqlx::Error> {
        let sql = format!("SELECT {COLUMNS} FROM kite_x402_settlement_v1 WHERE network = $1 AND transaction_hash = $2 ORDER BY (state = 'confirmed') DESC, (state = 'reported_success') DESC, id DESC LIMIT 1");
        sqlx::query(&sql)
            .bind(network)
            .bind(tx.to_ascii_lowercase())
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(Attempt::from_row)
            .transpose()
    }

    pub(crate) async fn summary(&self) -> Result<LedgerSummary, sqlx::Error> {
        // PostgreSQL NUMERIC has enough precision for each uint256 and SUM
        // yields unconstrained NUMERIC, so the sum may exceed uint256.
        let rows = sqlx::query(
            "SELECT network, asset, \
             (SUM(amount_atomic) FILTER (WHERE state IN ('reported_success', 'confirmed')))::text AS amount, \
             COUNT(*) FILTER (WHERE state IN ('reported_success', 'confirmed')) AS successes, \
             COUNT(*) FILTER (WHERE state IN ('settling', 'upstream_failed', 'canceled', 'transfer_mismatch')) AS failures \
             FROM kite_x402_settlement_v1 WHERE state NOT IN ('verifying', 'executing') \
             GROUP BY network, asset ORDER BY network, asset",
        ).fetch_all(&self.pool).await?;
        let mut summary = LedgerSummary {
            volumes: Vec::with_capacity(rows.len()),
            successful_count: 0,
            failed_count: 0,
        };
        for row in rows {
            summary.successful_count += row.try_get::<i64, _>("successes")?.unsigned_abs();
            summary.failed_count += row.try_get::<i64, _>("failures")?.unsigned_abs();
            if let Some(amount) = row.try_get::<Option<String>, _>("amount")? {
                summary.volumes.push(SettlementVolume {
                    network: row.try_get("network")?,
                    asset: row.try_get("asset")?,
                    amount_atomic: amount,
                });
            }
        }
        Ok(summary)
    }

    async fn claim(&self) -> Result<Option<Attempt>, sqlx::Error> {
        let sql = format!(
            "UPDATE kite_x402_settlement_v1 SET next_check_at = NOW() + INTERVAL '90 seconds' \
             WHERE id = (SELECT id FROM kite_x402_settlement_v1 WHERE state = 'settling' AND next_check_at <= NOW() \
                         ORDER BY next_check_at, id LIMIT 1 FOR UPDATE SKIP LOCKED) \
             RETURNING {COLUMNS}"
        );
        sqlx::query(&sql)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(Attempt::from_row)
            .transpose()
    }

    async fn reconcile_one(&self, attempt: Attempt) -> Result<(), SettlementStorageError> {
        let Some(from) = attempt.scan_from else {
            return Ok(());
        };
        match self.rpc.scan(&attempt.payment, from).await? {
            ScanResult::Wait => {}
            ScanResult::Advance(to) => {
                sqlx::query(
                    "UPDATE kite_x402_settlement_v1 SET scan_from = $2, next_check_at = NOW() \
                     WHERE id = $1 AND state = 'settling' AND scan_from = $3",
                )
                .bind(attempt.id)
                .bind(to)
                .bind(from)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;
            }
            ScanResult::Resolved { state, transaction } => {
                sqlx::query(
                    "UPDATE kite_x402_settlement_v1 SET state = $2, transaction_hash = $3, \
                     updated_at = NOW(), next_check_at = NULL WHERE id = $1 AND state = 'settling' AND scan_from = $4",
                ).bind(attempt.id).bind(state).bind(transaction).bind(from).execute(&self.pool).await.map_err(storage_error)?;
            }
        }
        Ok(())
    }

    async fn sweep(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM kite_x402_settlement_v1 WHERE id IN \
             (SELECT id FROM kite_x402_settlement_v1 WHERE state = 'verifying' AND lease_until <= NOW() \
              ORDER BY lease_until LIMIT 256 FOR UPDATE SKIP LOCKED)",
        ).execute(&self.pool).await?;
        for _ in 0..32 {
            let Some(attempt) = self.claim().await? else {
                break;
            };
            let id = attempt.id;
            if let Err(error) = self.reconcile_one(attempt).await {
                tracing::warn!(%error, id, "Settlement reconciliation will retry");
            }
        }
        Ok(())
    }

    pub(crate) async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.wait_for(|stopping| *stopping) => return,
                () = async {
                    interval.tick().await;
                    if let Err(error) = self.sweep().await {
                        tracing::error!(%error, "Could not scan settlement journal");
                    }
                } => {}
            }
        }
    }
}

fn storage_error(error: sqlx::Error) -> SettlementStorageError {
    SettlementStorageError(Box::new(error))
}

#[async_trait]
impl SettlementStore for DurableStore {
    async fn reserve(
        &self,
        p: &SettlementReconciliation,
    ) -> Result<Option<i64>, SettlementStorageError> {
        // A new ID fences workers whose verification ran longer than the lease.
        sqlx::query_scalar(
            "INSERT INTO kite_x402_settlement_v1 AS journal \
             (network, asset, payer, pay_to, nonce, amount_atomic, state, lease_until) \
             VALUES ($1, $2, $3, $4, $5, $6::text::numeric, 'verifying', NOW() + INTERVAL '5 minutes') \
             ON CONFLICT (network, asset, payer, nonce) DO UPDATE SET \
             id = EXCLUDED.id, lease_until = EXCLUDED.lease_until, pay_to = EXCLUDED.pay_to, \
             amount_atomic = EXCLUDED.amount_atomic, updated_at = NOW() \
             WHERE journal.state = 'verifying' AND journal.lease_until <= NOW() RETURNING id",
        ).bind(&p.network).bind(&p.asset).bind(&p.payer).bind(&p.pay_to)
            .bind(&p.nonce).bind(&p.amount_atomic).fetch_optional(&self.pool).await.map_err(storage_error)
    }

    async fn release(&self, id: i64) -> Result<(), SettlementStorageError> {
        sqlx::query("DELETE FROM kite_x402_settlement_v1 WHERE id = $1 AND state = 'verifying'")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    async fn begin_execution(
        &self,
        id: i64,
        payment: &SettlementReconciliation,
    ) -> Result<bool, SettlementStorageError> {
        let head = self.rpc.head(&payment.network).await?;
        // Include older blocks to tolerate shallow forks and small head discrepancies.
        let from = head.saturating_sub(32).max(0);
        let result = sqlx::query(
            "UPDATE kite_x402_settlement_v1 SET state = 'executing', scan_from = $2, updated_at = NOW() \
             WHERE id = $1 AND state = 'verifying' AND lease_until > NOW()",
        ).bind(id).bind(from).execute(&self.pool).await.map_err(storage_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn upstream_failed(&self, id: i64) -> Result<(), SettlementStorageError> {
        sqlx::query(
            "UPDATE kite_x402_settlement_v1 SET state = 'upstream_failed', updated_at = NOW() \
             WHERE id = $1 AND state = 'executing'",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    async fn begin_settlement(&self, id: i64) -> Result<(), SettlementStorageError> {
        let result = sqlx::query(
            "UPDATE kite_x402_settlement_v1 SET state = 'settling', \
             next_check_at = NOW(), updated_at = NOW() \
             WHERE id = $1 AND state = 'executing' AND scan_from IS NOT NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        if result.rows_affected() != 1 {
            return Err(SettlementStorageError(
                "Settlement intent lost its execution reservation".into(),
            ));
        }
        Ok(())
    }

    async fn finish_settlement(
        &self,
        id: i64,
        record: &SettlementRecord,
    ) -> Result<bool, SettlementStorageError> {
        let tx = normalized_hex(&record.tx_hash, 32);
        let updated = sqlx::query(
            "UPDATE kite_x402_settlement_v1 SET state = CASE WHEN $2 THEN 'reported_success' ELSE state END, \
             transaction_hash = $3, updated_at = NOW(), \
             next_check_at = CASE WHEN $2 THEN NULL ELSE NOW() END WHERE id = $1 AND state = 'settling'",
        ).bind(id).bind(record.success).bind(&tx)
            .execute(&self.pool).await.map_err(storage_error)?;
        if updated.rows_affected() == 1 || !record.success {
            return Ok(true);
        }
        // The read-only worker can resolve the attempt while /settle is in flight.
        // A purported success may only be returned if the proof agrees with it.
        let agrees: Option<bool> = sqlx::query_scalar(
            "SELECT state = 'confirmed' AND transaction_hash = $2 FROM kite_x402_settlement_v1 WHERE id = $1",
        ).bind(id).bind(tx).fetch_optional(&self.pool).await.map_err(storage_error)?;
        Ok(agrees.unwrap_or(false))
    }
}
