use crate::analyzers::eth::{EthInfo};

pub trait Analyzer {
    fn analyze_packet(&mut self, data: &[u8]);
}

pub struct BaseAnalyzer {
    eth_info: Option<EthInfo>,
}

impl BaseAnalyzer {
    pub fn new() -> BaseAnalyzer {
        BaseAnalyzer { eth_info: None }
    }

    pub fn eth_info(&self) -> Option<&EthInfo> {
        self.eth_info.as_ref()
    }
}

impl Analyzer for BaseAnalyzer {
    fn analyze_packet(&mut self, data: &[u8]) {
        let mut eth_info = EthInfo::new();
        eth_info.analyze_packet(data);
        self.eth_info = Some(eth_info);
    }
}
