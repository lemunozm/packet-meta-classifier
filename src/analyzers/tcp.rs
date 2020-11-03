use crate::analyzer::{Analyzer};

pub mod rules {
    use crate::rules::expression::{Value};
    use crate::analyzers::ip::{L4Analyzer};
    use crate::analyzer::{BaseAnalyzer};

    #[derive(Debug)]
    pub enum Tcp {
        SynFlood,
        Teardown,
    }

    impl Value<BaseAnalyzer> for Tcp {
        fn check_value(&self, analyzer: &BaseAnalyzer) -> bool {
            if let Some(eth_analyzer) = &analyzer.eth_analyzer() {
                if let Some(ip_analyzer) = &eth_analyzer.ip_analyzer() {
                    if let L4Analyzer::Tcp(tcp_analyzer) = ip_analyzer.l4_analyzer() {
                        return match self {
                            Tcp::SynFlood => tcp_analyzer.is_syn_flood,
                            Tcp::Teardown => tcp_analyzer.is_teardown,
                        }
                    }
                }
            }
            false
        }
    }
}

pub struct TcpAnalyzer {
    pub is_syn_flood: bool,
    pub is_teardown: bool,
}

impl Analyzer for TcpAnalyzer {
    fn analyze_packet(&mut self, data: &[u8]) {
        //TODO
    }
}
