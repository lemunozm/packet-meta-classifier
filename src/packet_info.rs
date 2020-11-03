use crate::analyzers::eth::{EthInfo};

pub trait Analyzer {
    fn analyze_packet(&mut self, data: &[u8]);
}

pub struct PacketInfo {
    eth_info: Option<EthInfo>,
}

impl PacketInfo {
    pub fn new() -> PacketInfo {
        PacketInfo { eth_info: None }
    }

    pub fn eth_info(&self) -> Option<&EthInfo> {
        self.eth_info.as_ref()
    }
}

impl Analyzer for PacketInfo {
    fn analyze_packet(&mut self, data: &[u8]) {
        let mut eth_info = EthInfo::new();
        eth_info.analyze_packet(data);
        self.eth_info = Some(eth_info);
    }
}
