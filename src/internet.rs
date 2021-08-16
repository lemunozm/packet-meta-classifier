/*
pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

use crate::classifier::id::ClassifierIdTrait;

#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub enum ClassifierId {
    None,
    Ip,
    Tcp,
    Udp,
    Http,
    Total,
}

impl From<usize> for ClassifierId {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Ip,
            2 => Self::Tcp,
            3 => Self::Udp,
            4 => Self::Http,
            _ => panic!("The value is not a valid ClassifierId"),
        }
    }
}

impl From<ClassifierId> for usize {
    fn from(id: ClassifierId) -> usize {
        id as usize
    }
}

impl ClassifierIdTrait for ClassifierId {
    const NONE: ClassifierId = ClassifierId::None;
    const INITIAL: ClassifierId = ClassifierId::Ip;
    const TOTAL: usize = ClassifierId::Total as usize;
}
*/
