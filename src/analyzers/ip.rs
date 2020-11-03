use crate::packet_info::{Analyzer};
use crate::analyzers::tcp::{TcpInfo};

use std::net::{IpAddr};

pub mod rules {
    use super::{L4Info, IpInfo};
    use crate::rules::expression::{Value};
    use crate::packet_info::{BaseAnalyzer};

    #[derive(Debug, PartialEq)]
    pub enum L4 {
        Udp,
        Tcp,
        Unknown,
    }

    #[derive(Debug)]
    pub enum Ip {
        Origin(String),
        Destination(String),
        L4(L4),
    }

    impl Ip {
        fn check(&self, ip_info: &IpInfo) -> bool {
            match self {
                Ip::Origin(regex) => match ip_info.ip_origin {
                    Some(ip) => true,
                    None => false,
                }
                Ip::Destination(regex) => match ip_info.ip_destination {
                    Some(ip) => true,
                    None => false,
                }
                Ip::L4(l4) => match ip_info.l4_info {
                    L4Info::Tcp(_) => *l4 == L4::Tcp,
                    L4Info::Udp(_) => *l4 == L4::Udp,
                    L4Info::Unknown => *l4 == L4::Unknown,
                }
            }
        }
    }

    impl Value<BaseAnalyzer> for Ip {
        fn check_value(&self, analyzer: &BaseAnalyzer) -> bool {
            match analyzer.eth_info() {
                Some(eth_info) => match eth_info.ip_info() {
                    Some(ip_info) => self.check(ip_info),
                    None => false
                }
                None => false,
            }
        }
    }
}

pub enum L4Info {
    Tcp(TcpInfo),
    Udp(()), //TODO
    Unknown,
}

pub struct IpInfo {
    ip_origin: Option<IpAddr>,
    ip_destination: Option<IpAddr>,
    l4_info: L4Info,
}

impl IpInfo {
    pub fn new() -> IpInfo {
        IpInfo {
            ip_origin: None,
            ip_destination: None,
            l4_info: L4Info::Unknown,
        }
    }

    pub fn l4_info(&self) -> &L4Info {
        &self.l4_info
    }
}

impl Analyzer for IpInfo {
    fn analyze_packet(&mut self, data: &[u8]) {
        //TODO
    }
}
