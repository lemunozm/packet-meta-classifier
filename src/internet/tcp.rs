pub mod analyzer {
    use super::flow::TcpFlow;

    use crate::core::base::analyzer::{Analyzer, AnalyzerStatus};
    use crate::core::packet::Packet;
    use crate::internet::ip::analyzer::IpAnalyzer;
    use crate::internet::ClassifierId;

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

        fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<ClassifierId> {
            self.source_port = u16::from_be_bytes(*array_ref![packet.data, 0, 2]);
            self.dest_port = u16::from_be_bytes(*array_ref![packet.data, 2, 2]);

            let header_len = (((packet.data[12] & 0xF0) as usize) >> 4) << 2;

            if self.source_port == 80 || self.source_port == 8080 {
                //AnalyzerStatus::Next(AnalyzerId::Http, data[header_len..])
                AnalyzerStatus::Finished(header_len)
            } else {
                AnalyzerStatus::Finished(header_len)
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

    use crate::core::base::flow::Flow;
    use crate::core::packet::Direction;
    use crate::internet::ClassifierId;

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

        fn create(_analyzer: &TcpAnalyzer, _direction: Direction) -> Self {
            TcpFlow {
                handshake: Handshake::Send,
            }
        }

        fn update(&mut self, _analyzer: &TcpAnalyzer, _direction: Direction) {
            //TODO
        }
    }
}

pub mod expression {
    use super::analyzer::TcpAnalyzer;
    use super::flow::TcpFlow;

    use crate::core::base::expression_value::ExpressionValue;
    use crate::internet::ClassifierId;

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
