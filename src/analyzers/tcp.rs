use crate::packet_info::{Analyzer};

pub mod rules {
    use crate::rules::rule::{RuleValue};
    use crate::analyzers::ip::{L4Info};
    use crate::packet_info::{PacketInfo};

    #[derive(Debug)]
    pub enum Tcp {
        SynFlood,
        Teardown,
    }

    impl RuleValue for Tcp {
        fn check_value(&self, packet_info: &PacketInfo) -> bool {
            if let Some(eth_info) = &packet_info.eth_info() {
                if let Some(ip_info) = &eth_info.ip_info() {
                    if let L4Info::Tcp(tcp_info) = ip_info.l4_info() {
                        return match self {
                            Tcp::SynFlood => tcp_info.is_syn_flood,
                            Tcp::Teardown => tcp_info.is_teardown,
                        }
                    }
                }
            }
            false
        }
    }
}

pub struct TcpInfo {
    pub is_syn_flood: bool,
    pub is_teardown: bool,
}

impl Analyzer for TcpInfo {
    fn analyze_packet(&mut self, data: &[u8]) {
        //TODO
    }
}
