use crate::analyzer::{Analyzer};
use crate::analyzers::ip::{IpAnalyzer};

pub mod rules {
    use crate::rules::expression::{Value};
    use crate::analyzer::{BaseAnalyzer};

    #[derive(Debug, PartialEq)]
    pub enum L3 {
        Ip,
        Unknown,
    }

    #[derive(Debug)]
    pub enum Eth {
        L3(L3),
    }

    impl Value<BaseAnalyzer> for Eth {
        fn check_value(&self, analyzer: &BaseAnalyzer) -> bool {
            if let Some(eth_analyzer) = &analyzer.eth_analyzer() {
                return match self {
                    Eth::L3(l3) => *l3 == L3::Ip && eth_analyzer.ip_analyzer.is_some()
                }
            }
            false
        }
    }
}

pub struct EthAnalyzer {
    ip_analyzer: Option<IpAnalyzer>,
}

impl EthAnalyzer {
    pub fn new() -> EthAnalyzer {
        EthAnalyzer { ip_analyzer: None }
    }

    pub fn ip_analyzer(&self) -> Option<&IpAnalyzer> {
        self.ip_analyzer.as_ref()
    }
}

const CHECKSUM_LEN: usize = 4;

impl Analyzer for EthAnalyzer {
    fn analyze_packet(&mut self, l2_data: &[u8]) {
        let ether_type = &l2_data[12..14];
        let l3_data = &l2_data[15..l2_data.len() - CHECKSUM_LEN];
        match ether_type {
           [0x08, 0x00] => {
                let mut ip_analyzer = IpAnalyzer::new();
                ip_analyzer.analyze_packet(l3_data);
                self.ip_analyzer = Some(ip_analyzer);
           }
           _ => (),
        }

        //TODO
    }
}
