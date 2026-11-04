pub struct ZeroCopySlice<'a> {
    data: &'a [u8],
}

impl<'a> ZeroCopySlice<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Validates UTF-8 without heap cloning
    pub fn as_str(&self) -> Result<&'a str, std::str::Utf8Error> {
        std::str::from_utf8(self.data)
    }

    /// Fast prefix scanner
    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        self.data.starts_with(prefix)
    }
}
