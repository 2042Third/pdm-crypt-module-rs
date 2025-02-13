#[derive(Default)]
pub struct CryptoConfig {
    poly1305_toggle: bool,
    display_prog: bool,
    pure_xor: bool,
    de: bool,
    is_xchacha: bool,
    // Add more options
    buffer_size: usize,
    iterations: u32,
}

// Implementation for Config
impl CryptoConfig {
    pub fn new() -> Self {
        Self::default()
    }

    // Builder pattern methods
    pub fn with_poly1305(mut self, enable: bool) -> Self {
        self.poly1305_toggle = enable;
        self
    }

    pub fn with_display_prog(mut self, enable: bool) -> Self {
        self.display_prog = enable;
        self
    }

    pub fn with_pure_xor(mut self, enable: bool) -> Self {
        self.pure_xor = enable;
        self
    }

    pub fn with_de(mut self, enable: bool) -> Self {
        self.de = enable;
        self
    }

    pub fn with_xchacha(mut self, enable: bool) -> Self {
        self.is_xchacha = enable;
        self
    }
}
