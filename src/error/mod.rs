
/// Enum that represents some Types of Error in Tequel.
#[derive(Debug)]
pub enum TequelError {
    /// When Hash is invalid
    InvalidHash,

    /// When occurr some error with the decode from HEX to UTF-8
    InvalidHex(String),

    /// When MACs not match
    InvalidMac,

    /// When occurr error while trying decode HEX to UTF-8
    InvalidUtf8,

    /// When key is don't provided or is different
    KeyError(String),

}

impl std::fmt::Display for TequelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TequelError::InvalidHash => write!(f, "Hash is Invalid"),
            TequelError::InvalidHex(s) => write!(f, "Hex is Invalid: {}", s),
            TequelError::InvalidMac => write!(f, "MACs not match. Data has changed! Key? Data?"),
            TequelError::InvalidUtf8 => write!(f, "Error UTF-8 convertion. Incorrect Key?"),
            TequelError::KeyError(e) => write!(f, "Key Error: {}", e)
        }
    }
}


impl std::error::Error for TequelError {}