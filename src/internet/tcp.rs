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

    impl Analyzer<ClassifierId> for TcpAnalyzer {
        type PrevAnalyzer = IpAnalyzer;
        type Flow = TcpFlow;
        const ID: ClassifierId = ClassifierId::Tcp;

        fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a, ClassifierId> {
            self.source_port = u16::from_be_bytes(*array_ref![data, 0, 2]);
            self.dest_port = u16::from_be_bytes(*array_ref![data, 2, 2]);

            let header_len = (((data[12] & 0xF0) as usize) >> 4) << 2;

            if self.source_port == 80 || self.source_port == 8080 {
                //AnalyzerStatus::Next(AnalyzerId::Http, data[header_len..])
                AnalyzerStatus::Finished(&data[header_len..])
            } else {
                AnalyzerStatus::Finished(&data[header_len..])
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
    use crate::classifiers::ClassifierId;

    use crate::flow::Flow;

    pub enum Handshake {
        Send,
        Recv,
        Established,
    }

    pub struct TcpFlow {
        pub handshake: Handshake,
    }

    impl Flow<ClassifierId> for TcpFlow {
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

pub mod expression {
    use super::analyzer::TcpAnalyzer;
    use super::flow::TcpFlow;

    use crate::classifiers::ClassifierId;
    use crate::expression::ExpressionValue;

    #[derive(Debug)]
    pub struct Tcp;

    impl ExpressionValue<ClassifierId> for Tcp {
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

    impl ExpressionValue<ClassifierId> for TcpSourcePort {
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

    impl ExpressionValue<ClassifierId> for TcpDestPort {
        type Analyzer = TcpAnalyzer;

        fn description() -> &'static str {
            "Valid if the destination TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.dest_port
        }
    }
}
