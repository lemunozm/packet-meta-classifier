pub trait Analyzer {
    fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8];
}

use crate::classifiers::ipv4::analyzer::{Ipv4Analyzer};
use crate::classifiers::tcp::analyzer::{TcpAnalyzer};

use std::net::{IpAddr};

#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4 {
    Udp,
    Tcp,
    Unknown,
}

impl L4 {
    pub fn from_value(protocol: u8) -> L4 {
        match protocol {
            6 => L4::Tcp,
            _ => L4::Unknown,
        }
    }
}

pub enum L3Analyzer {
    Ipv4(Ipv4Analyzer),
    None,
}

impl L3Analyzer {
    pub fn next_header(&self) -> L4 {
        match self {
           L3Analyzer::Ipv4(ipv4) => ipv4.protocol,
           _ => L4::Unknown
        }
    }
}

pub enum L4Analyzer {
    Tcp(TcpAnalyzer),
    None,
}

impl L4Analyzer {
    pub fn tcp(&self) -> &TcpAnalyzer {
        match self {
            L4Analyzer::Tcp(tcp) => tcp,
            _ => panic!("L4 must be tcp"),
        }
    }
}

#[derive(Hash, Clone, PartialEq, Eq)]
pub struct FiveTuple {
    pub protocol: L4,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
}

pub struct AnalyzerPipeline {
    l3: L3Analyzer,
    l4: L4Analyzer
}

impl AnalyzerPipeline {
    pub fn new() -> AnalyzerPipeline {
        AnalyzerPipeline {
            l3: L3Analyzer::None,
            l4: L4Analyzer::None,
        }
    }

    pub fn l3(&self) -> &L3Analyzer {
        &self.l3
    }

    pub fn l4(&self) -> &L4Analyzer {
        &self.l4
    }

    pub fn five_tuple(&self) -> Option<FiveTuple> {
        let (protocol, source_ip, destination_ip) = match self.l3() {
            L3Analyzer::Ipv4(ip) => (
                ip.protocol,
                ip.source,
                ip.destination,
            ),
            _ => return None,
        };

        let (source_port, destination_port) = match self.l4() {
            L4Analyzer::Tcp(tcp) => (
                tcp.source_port,
                tcp.destination_port,
            ),
            _ => return None,
        };

        Some(FiveTuple {
            protocol,
            source_ip: IpAddr::from(source_ip),
            destination_ip: IpAddr::from(destination_ip),
            source_port,
            destination_port,
        })
    }

    pub fn analyze_l3<'a>(&mut self, mut data: &'a[u8]) -> &'a[u8] {
        let ip_version = data[0] & 0x0F;
        self.l3 = match ip_version {
            4 => {
                let mut ipv4 = Ipv4Analyzer::new();
                data = ipv4.analyze_packet(data);
                L3Analyzer::Ipv4(ipv4)
            },
            _ => L3Analyzer::None
        };
        data
    }

    pub fn analyze_l4<'a>(&mut self, mut data: &'a[u8]) -> &'a[u8] {
        self.l4 = match self.l3().next_header() {
            L4::Tcp => {
                let mut tcp = TcpAnalyzer::new();
                data = tcp.analyze_packet(data);
                L4Analyzer::Tcp(tcp)
            }
            _ => L4Analyzer::None
        };
        data
    }
}
