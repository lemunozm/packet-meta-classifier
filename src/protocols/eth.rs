use crate::packet_info::{Analyzer};
use crate::protocols::ip::{IpInfo};

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

impl Analyzer for EthInfo {
    fn analyze_packet(&mut self, data: &[u8]) {
        //TODO
    }
}
