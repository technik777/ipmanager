use std::{fmt, str::FromStr};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

#[derive(Debug, thiserror::Error)]
pub enum MacParseError {
    #[error("invalid mac length")]
    InvalidLength,
    #[error("invalid hex digit")]
    InvalidHex,
}

impl MacAddr {
    pub fn bytes(&self) -> [u8; 6] {
        self.0
    }

    fn parse_hex_pair(a: u8, b: u8) -> Result<u8, MacParseError> {
        fn val(x: u8) -> Result<u8, MacParseError> {
            match x {
                b'0'..=b'9' => Ok(x - b'0'),
                b'a'..=b'f' => Ok(10 + (x - b'a')),
                b'A'..=b'F' => Ok(10 + (x - b'A')),
                _ => Err(MacParseError::InvalidHex),
            }
        }
        Ok((val(a)? << 4) | val(b)?)
    }
}

impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input.trim();

        // 12 hex chars
        if s.len() == 12 && s.as_bytes().iter().all(|c| c.is_ascii_hexdigit()) {
            let b = s.as_bytes();
            let mut out = [0u8; 6];
            for i in 0..6 {
                out[i] = MacAddr::parse_hex_pair(b[i * 2], b[i * 2 + 1])?;
            }
            return Ok(MacAddr(out));
        }

        // Separator path
        if s.len() != 17 {
            return Err(MacParseError::InvalidLength);
        }

        let bytes = s.as_bytes();
        let sep = bytes[2];
        if sep != b':' && sep != b'-' {
            return Err(MacParseError::InvalidHex);
        }

        for &idx in &[2usize, 5, 8, 11, 14] {
            if bytes[idx] != sep {
                return Err(MacParseError::InvalidLength);
            }
        }

        let mut out = [0u8; 6];
        let mut j = 0usize;
        for i in (0..17).step_by(3) {
            out[j] = MacAddr::parse_hex_pair(bytes[i], bytes[i + 1])?;
            j += 1;
        }
        Ok(MacAddr(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({})", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_format() {
        let m = "AA:bb:CC:dd:EE:ff".parse::<MacAddr>().unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parses_dash_format() {
        let m = "aa-bb-cc-dd-ee-ff".parse::<MacAddr>().unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parses_plain_hex() {
        let m = "aabbccddeeff".parse::<MacAddr>().unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn rejects_wrong_length() {
        let err = "aa:bb:cc:dd:ee".parse::<MacAddr>().unwrap_err();
        matches!(err, MacParseError::InvalidLength);
    }

    #[test]
    fn rejects_invalid_hex() {
        let err = "aa:bb:cc:dd:ee:gg".parse::<MacAddr>().unwrap_err();
        matches!(err, MacParseError::InvalidHex);
    }

    #[test]
    fn rejects_mixed_separators() {
        let err = "aa:bb-cc:dd-ee:ff".parse::<MacAddr>().unwrap_err();
        matches!(err, MacParseError::InvalidLength);
    }
}
