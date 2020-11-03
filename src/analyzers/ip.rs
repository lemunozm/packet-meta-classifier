use crate::analyzer::{Analyzer};
use crate::analyzers::tcp::{TcpAnalyzer};

use std::net::{IpAddr};

pub mod rules {
    use super::{L4Analyzer, IpAnalyzer};
    use crate::rules::expression::{Value};
    use crate::analyzer::{BaseAnalyzer};

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
        fn check(&self, ip_analyzer: &IpAnalyzer) -> bool {
            match self {
                Ip::Origin(regex) => match ip_analyzer.ip_origin {
                    Some(ip) => true,
                    None => false,
                }
                Ip::Destination(regex) => match ip_analyzer.ip_destination {
                    Some(ip) => true,
                    None => false,
                }
                Ip::L4(l4) => match ip_analyzer.l4_analyzer {
                    L4Analyzer::Tcp(_) => *l4 == L4::Tcp,
                    L4Analyzer::Udp(_) => *l4 == L4::Udp,
                    L4Analyzer::Unknown => *l4 == L4::Unknown,
                }
            }
        }
    }

    impl Value<BaseAnalyzer> for Ip {
        fn check_value(&self, analyzer: &BaseAnalyzer) -> bool {
            match analyzer.eth_analyzer() {
                Some(eth_analyzer) => match eth_analyzer.ip_analyzer() {
                    Some(ip_analyzer) => self.check(ip_analyzer),
                    None => false
                }
                None => false,
            }
        }
    }
}

pub enum L4Analyzer {
    Tcp(TcpAnalyzer),
    Udp(()), //TODO
    Unknown,
}

pub struct IpAnalyzer {
    ip_origin: Option<IpAddr>,
    ip_destination: Option<IpAddr>,
    l4_analyzer: L4Analyzer,
}

impl IpAnalyzer {
    pub fn new() -> IpAnalyzer {
        IpAnalyzer {
            ip_origin: None,
            ip_destination: None,
            l4_analyzer: L4Analyzer::Unknown,
        }
    }

    pub fn l4_analyzer(&self) -> &L4Analyzer {
        &self.l4_analyzer
    }
}

impl Analyzer for IpAnalyzer {
    fn analyze_packet(&mut self, data: &[u8]) {
        //TODO
    }
}
