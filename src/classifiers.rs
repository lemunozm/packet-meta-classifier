pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd)]
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
