use crate::packet_info::{Analyzer};
use crate::analyzers::ip::{IpInfo};

pub mod rules {
    use crate::rules::rule::{RuleValue};
    use crate::packet_info::{PacketInfo};

    #[derive(Debug, PartialEq)]
    pub enum L3 {
        Ip,
        Unknown,
    }

    #[derive(Debug)]
    pub enum Eth {
        L3(L3),
    }

    impl RuleValue for Eth {
        fn check_value(&self, packet_info: &PacketInfo) -> bool {
            if let Some(eth_info) = &packet_info.eth_info() {
                return match self {
                    Eth::L3(l3) => *l3 == L3::Ip && eth_info.ip_info.is_some()
                }
            }
            false
        }
    }
}

pub struct EthInfo {
    ip_info: Option<IpInfo>,
}

impl EthInfo {
    pub fn new() -> EthInfo {
        EthInfo { ip_info: None }
    }

    pub fn ip_info(&self) -> Option<&IpInfo> {
        self.ip_info.as_ref()
    }
}

const CHECKSUM_LEN: usize = 4;

impl Analyzer for EthInfo {
    fn analyze_packet(&mut self, l2_data: &[u8]) {
        let ether_type = &l2_data[12..14];
        let l3_data = &l2_data[15..l2_data.len() - CHECKSUM_LEN];
        match ether_type {
           [0x08, 0x00] => {
                let mut ip_info = IpInfo::new();
                ip_info.analyze_packet(l3_data);
                self.ip_info = Some(ip_info);
           }
           _ => (),
        }

        //TODO
    }
}
