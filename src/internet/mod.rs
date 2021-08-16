pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

use crate::core::base::id::ClassifierId as ClassifierIdTrait;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use strum::EnumCount;

#[derive(EnumCount, FromPrimitive, Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub enum ClassifierId {
    None,
    Ip,
    Tcp,
    Udp,
    Http,
}

impl From<usize> for ClassifierId {
    fn from(value: usize) -> Self {
        Self::from_usize(value).expect("The value must be a valid ClassifierId")
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
    const TOTAL: usize = ClassifierId::COUNT;
}
