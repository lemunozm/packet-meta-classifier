use std::net::{IpAddr};

#[derive(Debug, PartialEq)]
pub enum L4 {
    Udp,
    Tcp,
}

pub struct IpInfo {
    pub ip_origin: Option<IpAddr>,
    pub ip_destination: Option<IpAddr>,
    pub l4: L4,
}

pub struct TcpInfo {
    pub is_syn_flood: bool,
    pub is_teardown: bool,
}

pub struct PacketInfo {
    pub ip: Option<IpInfo>,
    pub tcp: Option<TcpInfo>,
}

