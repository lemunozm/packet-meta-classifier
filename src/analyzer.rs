pub trait Analyzer {
    fn analyze_packet(&mut self, data: &[u8]);
}

use crate::analyzers::eth::{EthAnalyzer};

pub struct BaseAnalyzer {
    eth_analyzer: Option<EthAnalyzer>,
}

impl BaseAnalyzer {
    pub fn new() -> BaseAnalyzer {
        BaseAnalyzer { eth_analyzer: None }
    }

    pub fn eth_analyzer(&self) -> Option<&EthAnalyzer> {
        self.eth_analyzer.as_ref()
    }
}

impl Analyzer for BaseAnalyzer {
    fn analyze_packet(&mut self, data: &[u8]) {
        let mut eth_analyzer = EthAnalyzer::new();
        eth_analyzer.analyze_packet(data);
        self.eth_analyzer = Some(eth_analyzer);
    }
}
