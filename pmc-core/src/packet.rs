use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    Uplink,
    Downlink,
}

impl From<bool> for Direction {
    fn from(value: bool) -> Self {
        match value {
            true => Self::Uplink,
            false => Self::Downlink,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uplink => write!(f, "uplink"),
            Self::Downlink => write!(f, "downlink"),
        }
    }
}

pub struct Packet<'a> {
    pub data: &'a [u8],
    pub direction: Direction,
}
