pub trait Analyzer {
    fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8];
}

use crate::classifiers::ip::analyzer::{IpAnalyzer};
use crate::classifiers::tcp::analyzer::{TcpAnalyzer};

use std::net::{IpAddr};

#[derive(Hash, Clone, PartialEq, Eq)]
pub struct FiveTuple {
    pub protocol: L4,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4 {
    Udp,
    Tcp,
    Dns,
    Unknown,
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

pub struct AnalyzerPipeline {
    ip: IpAnalyzer,
    l4: L4Analyzer
}

impl AnalyzerPipeline {
    pub fn new() -> AnalyzerPipeline {
        AnalyzerPipeline {
            ip: IpAnalyzer::new(),
            l4: L4Analyzer::None,
        }
    }

    pub fn l3(&self) -> &IpAnalyzer {
        &self.ip
    }

    pub fn l4(&self) -> &L4Analyzer {
        &self.l4
    }

    pub fn five_tuple(&self) -> Option<FiveTuple> {
        let (source_port, destination_port) = match self.l4() {
            L4Analyzer::Tcp(tcp) => (
                tcp.source_port,
                tcp.destination_port,
            ),
            _ => return None,
        };

        Some(FiveTuple {
            protocol: self.ip.protocol,
            source_ip: IpAddr::from(self.ip.source),
            destination_ip: IpAddr::from(self.ip.destination),
            source_port,
            destination_port,
        })
    }

    pub fn analyze_l3<'a>(&mut self, data: &'a[u8]) -> &'a[u8] {
        self.ip.analyze_packet(data)
    }

    pub fn analyze_l4<'a>(&mut self, mut data: &'a[u8]) -> &'a[u8] {
        self.l4 = match self.ip.protocol {
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
