use crate::ClassifierId;

use pmc_core::base::classifier::Classifier;

pub struct TcpClassifier;
impl<'a> Classifier<'a, ClassifierId> for TcpClassifier {
    type Analyzer = analyzer::TcpAnalyzer<'a>;
}

mod analyzer {
    use super::flow::TcpFlow;

    use crate::{ClassifierId, FlowSignature};

    use pmc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
    use pmc_core::packet::{Direction, Packet};

    bitflags::bitflags! {
        pub struct Flag: u8 {
            const FIN = 1 << 0;
            const SYN = 1 << 1;
            const RST = 1 << 2;
            const PSH = 1 << 3;
            const ACK = 1 << 4;
            const URG = 1 << 5;
            const ECE = 1 << 6;
            const CWR = 1 << 7;
        }
    }

    pub struct TcpAnalyzer<'a> {
        pub header: &'a [u8],
        pub payload_len: u16,
        pub direction: Direction,
    }

    impl<'a> TcpAnalyzer<'a> {
        pub fn source_port(&self) -> u16 {
            u16::from_be_bytes(*array_ref![self.header, 0, 2])
        }

        pub fn dest_port(&self) -> u16 {
            u16::from_be_bytes(*array_ref![self.header, 2, 2])
        }

        pub fn server_port(&self) -> u16 {
            match self.direction {
                Direction::Uplink => self.dest_port(),
                Direction::Downlink => self.source_port(),
            }
        }

        pub fn payload_len(&self) -> u16 {
            self.payload_len
        }

        pub fn flags(&self) -> Flag {
            Flag::from_bits(self.header[13]).unwrap()
        }

        fn expected_l7_classifier(server_port: u16) -> ClassifierId {
            match server_port {
                80 => ClassifierId::HttpStartLine,
                8080 => ClassifierId::HttpStartLine,
                _ => ClassifierId::None,
            }
        }
    }

    impl<'a> Analyzer<'a, ClassifierId> for TcpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Tcp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;

        type Flow = TcpFlow;

        fn build(&Packet { data, direction }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            let header_len = (((data[12] & 0xF0) as usize) >> 4) << 2;

            let analyzer = Self {
                header: &data[0..header_len],
                payload_len: (data.len() - header_len) as u16,
                direction,
            };

            let next_protocol = match analyzer.payload_len > 0 {
                true => Self::expected_l7_classifier(analyzer.server_port()),
                false => ClassifierId::None,
            };

            Ok(AnalyzerInfo {
                analyzer,
                next_classifier_id: next_protocol,
                bytes_parsed: header_len,
            })
        }

        fn update_flow_id(&self, signature: &mut FlowSignature, direction: Direction) -> bool {
            let (source, dest) = (self.source_port(), self.dest_port());
            let (first, second) = match direction {
                Direction::Uplink => (source, dest),
                Direction::Downlink => (dest, source),
            };

            signature.source_port = first;
            signature.dest_port = second;

            true
        }

        fn update_flow(&self, flow: &mut TcpFlow, direction: Direction) {
            flow.update_handshake_state(direction, self.flags());
        }
    }
}

mod flow {
    use super::analyzer::Flag;

    use pmc_core::packet::Direction;

    #[derive(Clone, Copy, PartialEq)]
    pub enum Handshake {
        None,
        Send,
        Recv,
        Established,
    }

    pub struct TcpFlow {
        handshake: Handshake,
    }

    impl Default for TcpFlow {
        fn default() -> Self {
            TcpFlow {
                handshake: Handshake::None,
            }
        }
    }

    impl TcpFlow {
        pub fn update_handshake_state(&mut self, direction: Direction, flags: Flag) {
            let uplink = direction == Direction::Uplink;
            self.handshake = match self.handshake {
                Handshake::None if uplink && flags == Flag::SYN => Handshake::Send,
                Handshake::Send if !uplink && flags == Flag::SYN | Flag::ACK => Handshake::Recv,
                Handshake::Recv if uplink && flags == Flag::ACK => Handshake::Established,
                _ => self.handshake,
            }
        }

        pub fn handshake(&self) -> Handshake {
            self.handshake
        }
    }
}

pub mod expression {
    use super::analyzer::TcpAnalyzer;
    use super::flow::{Handshake, TcpFlow};
    use super::TcpClassifier;

    use crate::ClassifierId;

    use pmc_core::base::expression_value::ExpressionValue;

    use std::fmt;

    #[derive(Debug)]
    pub struct TcpSourcePort(pub u16);

    impl ExpressionValue<ClassifierId> for TcpSourcePort {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the source TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.source_port()
        }
    }

    #[derive(Debug)]
    pub struct TcpDestPort(pub u16);

    impl ExpressionValue<ClassifierId> for TcpDestPort {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the destination TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.dest_port()
        }
    }

    #[derive(Debug)]
    pub struct TcpServerPort(pub u16);

    impl ExpressionValue<ClassifierId> for TcpServerPort {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the server TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.server_port()
        }
    }

    pub struct TcpPayloadLen<F>(pub F);

    impl<F> fmt::Debug for TcpPayloadLen<F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            write!(f, "TcpPayloadLen(USER_FN)")
        }
    }

    impl<F> ExpressionValue<ClassifierId> for TcpPayloadLen<F>
    where
        F: Fn(u16) -> bool + 'static,
    {
        type Classifier = super::TcpClassifier;

        fn description() -> &'static str {
            "Valid if the payload len meets the user assert"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0(analyzer.payload_len())
        }
    }

    #[derive(Debug)]
    pub struct TcpEstablished;

    impl ExpressionValue<ClassifierId> for TcpEstablished {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the server TCP port of the packet matches the given port"
        }

        fn check(&self, _analyzer: &TcpAnalyzer, flow: &TcpFlow) -> bool {
            Handshake::Established == flow.handshake()
        }
    }
}
