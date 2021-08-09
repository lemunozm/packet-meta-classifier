pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

#[derive(strum::EnumCount, num_derive::FromPrimitive, Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ClassifierId {
    Ip,
    Tcp,
    Udp,
    Http,
}

impl From<ClassifierId> for usize {
    fn from(id: ClassifierId) -> usize {
        id as usize
    }
}

impl From<usize> for ClassifierId {
    fn from(number: usize) -> ClassifierId {
        num_traits::FromPrimitive::from_usize(number)
            .expect("The number must represent a Classifier ID")
    }
}
