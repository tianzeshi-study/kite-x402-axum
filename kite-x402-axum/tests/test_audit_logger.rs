use kite_x402_axum::audit_logger::AuditLogger;

#[test]
fn test_audit_logger_creates_records() {
    let logger = AuditLogger::new();
    let record = logger.build_record(
        "trace-101",
        "payment_verify",
        Some("0x1234".to_string()),
        Some("1.00".to_string()),
        "kite-testnet",
        "success",
        24,
    );

    assert_eq!(record.trace_id, "trace-101");
    assert_eq!(record.network, "kite-testnet");
    assert_eq!(record.status, "success");
    assert_eq!(logger.total_emitted(), 1);
}
