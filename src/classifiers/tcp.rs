pub mod analyzer {
    use super::flow::TcpFlow;

    use crate::analyzer::{Analyzer, AnalyzerStatus};
    use crate::classifiers::ip::analyzer::IpAnalyzer;
    use crate::classifiers::ClassifierId;

    use std::io::Write;

    #[derive(Default)]
    pub struct TcpAnalyzer {
        pub source_port: u16,
        pub dest_port: u16,
    }

    impl Analyzer for TcpAnalyzer {
        type PrevAnalyzer = IpAnalyzer;
        type Flow = TcpFlow;
        const ID: ClassifierId = ClassifierId::Tcp;

        fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a> {
            self.source_port = u16::from_be_bytes(*array_ref![data, 0, 2]);
            self.dest_port = u16::from_be_bytes(*array_ref![data, 2, 2]);

            let header_length = (((data[12] & 0xF0) as usize) >> 4) << 2;

            if self.source_port == 80 || self.source_port == 8080 {
                //AnalyzerStatus::Next(AnalyzerId::Http, data[header_length..])
                AnalyzerStatus::Finished(&data[header_length..])
            } else {
                AnalyzerStatus::Finished(&data[header_length..])
            }
        }

        fn write_flow_signature(&self, mut signature: impl Write) -> bool {
            signature.write(&self.source_port.to_le_bytes()).unwrap();
            signature.write(&self.dest_port.to_le_bytes()).unwrap();
            true
        }
    }
}

pub mod flow {
    use super::analyzer::TcpAnalyzer;

    use crate::flow::Flow;

    pub enum Handshake {
        Send,
        Recv,
        Established,
    }

    pub struct TcpFlow {
        pub handshake: Handshake,
    }

    impl Flow for TcpFlow {
        type Analyzer = TcpAnalyzer;

        fn create(_analyzer: &TcpAnalyzer) -> Self {
            TcpFlow {
                handshake: Handshake::Send,
            }
        }

        fn update(&mut self, _analyzer: &TcpAnalyzer) {
            //TODO
        }
    }
}

pub mod rules {
    use super::analyzer::TcpAnalyzer;
    use super::flow::TcpFlow;

    use crate::expression::ExprValue;

    #[derive(Debug)]
    pub struct Tcp;

    impl ExprValue for Tcp {
        type Flow = TcpFlow;
        type Analyzer = TcpAnalyzer;

        fn description() -> &'static str {
            "Valid if the packet is TCP"
        }

        fn check(&self, _analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub struct TcpSourcePort(pub u16);

    impl ExprValue for TcpSourcePort {
        type Flow = TcpFlow;
        type Analyzer = TcpAnalyzer;

        fn description() -> &'static str {
            "Valid if the source TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.source_port
        }
    }

    #[derive(Debug)]
    pub struct TcpDestPort(pub u16);

    impl ExprValue for TcpDestPort {
        type Flow = TcpFlow;
        type Analyzer = TcpAnalyzer;

        fn description() -> &'static str {
            "Valid if the destination TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.dest_port
        }
    }
}
