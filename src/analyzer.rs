pub trait Analyzer {
    fn analyze_packet<'a>(&mut self, data: &'a[u8]) -> &'a[u8];
}

use crate::classifiers::ip::{L4, analyzer::{IpAnalyzer}};
use crate::classifiers::tcp::analyzer::{TcpAnalyzer};

use std::net::{IpAddr};

#[derive(Hash, Clone)]
pub struct FiveTuple {
    pub protocol: L4,
    pub origin_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub origin_port: u16,
    pub destination_port: u16,
}

pub enum L4Analyzer {
    Tcp(TcpAnalyzer),
    None,
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
        let (origin_port, destination_port) = match self.l4() {
            L4Analyzer::Tcp(tcp) => (
                tcp.origin_port.unwrap(),
                tcp.destination_port.unwrap(),
            ),
            _ => return None,
        };

        Some(FiveTuple {
            protocol: self.ip.protocol,
            origin_ip: self.ip.origin.unwrap(),
            destination_ip: self.ip.destination.unwrap(),
            origin_port,
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
