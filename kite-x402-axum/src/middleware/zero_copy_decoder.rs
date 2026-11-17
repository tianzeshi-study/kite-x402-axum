//! Borrowed inspection of bytes; not a settlement schema validator.
/// A borrowed payload view that never copies its byte buffer.
#[derive(Debug, Clone, Copy)]
pub struct ZeroCopySlice<'a> {
    data: &'a [u8],
}
impl<'a> ZeroCopySlice<'a> {
    /// Borrows a byte slice.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    /// Returns the byte count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }
    /// Returns whether the slice is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    /// Validates UTF-8 without allocating.
    pub fn as_str(&self) -> Result<&'a str, std::str::Utf8Error> {
        std::str::from_utf8(self.data)
    }
    /// Checks a byte prefix.
    #[must_use]
    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        self.data.starts_with(prefix)
    }
}
