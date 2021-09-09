use crate::Config;

use pmc_core::base::classifier::Classifier;

pub struct TcpClassifier;
impl<'a> Classifier<'a, Config> for TcpClassifier {
    type Analyzer = analyzer::TcpAnalyzer<'a>;
}

mod analyzer {
    use super::flow::TcpFlow;

    use crate::{ClassifierId, Config, FlowSignature};

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

        pub fn seq_num(&self) -> u32 {
            u32::from_be_bytes(*array_ref![self.header, 4, 4])
        }

        pub fn ack_num(&self) -> u32 {
            u32::from_be_bytes(*array_ref![self.header, 8, 4])
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

    impl<'a> Analyzer<'a, Config> for TcpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Tcp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;

        type Flow = TcpFlow;

        fn build(
            _config: &Config,
            &Packet { data, direction }: &'a Packet,
        ) -> AnalyzerResult<Self, ClassifierId> {
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

        fn update_flow(&self, _config: &Config, flow: &mut TcpFlow, direction: Direction) {
            flow.update_seq_nums(
                direction,
                self.seq_num(),
                self.ack_num(),
                self.payload_len,
                self.flags(),
            );

            if flow.is_last_packet_expected() {
                flow.update_state_transition(direction, self.flags());
            }
        }
    }
}

mod flow {
    use super::analyzer::Flag;

    use pmc_core::packet::Direction;

    #[derive(Clone, Copy, PartialEq)]
    pub enum StateTransition {
        Listen,
        SynSend,
        SynRecv,
        Established,
        FinWait1,
        FinWait2,
        Closing,
        TimeWait,
    }
    use StateTransition::*;

    pub enum PacketStatus {
        Expected,
        Retransmission,
    }

    pub struct TcpFlow {
        prev_state_transition: StateTransition,
        state_transition: StateTransition,
        ul_seq_num: u32,
        dl_seq_num: u32,
        last_packet_status: PacketStatus,
    }

    impl Default for TcpFlow {
        fn default() -> Self {
            TcpFlow {
                prev_state_transition: StateTransition::Listen,
                state_transition: StateTransition::Listen,
                ul_seq_num: 0,
                dl_seq_num: 0,
                last_packet_status: PacketStatus::Expected,
            }
        }
    }

    impl TcpFlow {
        pub fn update_state_transition(&mut self, direction: Direction, flags: Flag) {
            let uplink = direction == Direction::Uplink;
            self.prev_state_transition = self.state_transition;
            self.state_transition = match self.state_transition {
                // Handshake:
                Listen if uplink && flags == Flag::SYN => SynSend,
                SynSend if !uplink && flags == Flag::SYN | Flag::ACK => SynRecv,
                SynRecv if uplink && flags == Flag::ACK => Established,
                // Teardown:
                Established if flags == Flag::FIN | Flag::ACK => FinWait1,
                FinWait1 if flags == Flag::ACK => FinWait2,
                FinWait1 if flags == Flag::FIN | Flag::ACK => Closing,
                FinWait2 if flags == Flag::FIN | Flag::ACK => TimeWait,
                Closing if flags == Flag::ACK => TimeWait,
                _ => self.state_transition,
            }
        }

        pub fn update_seq_nums(
            &mut self,
            direction: Direction,
            seq_num: u32,
            ack_num: u32,
            payload_len: u16,
            flags: Flag,
        ) {
            let syn = flags.contains(Flag::SYN);
            let len = match syn || flags.contains(Flag::FIN) {
                true => 1,
                false => payload_len as u32,
            };

            match direction {
                Direction::Uplink => {
                    if self.ul_seq_num == seq_num && self.dl_seq_num == ack_num || syn {
                        if len > 0 {
                            self.ul_seq_num = seq_num + len;
                            self.dl_seq_num = ack_num;
                        }
                        self.last_packet_status = PacketStatus::Expected;
                        return;
                    }
                }
                Direction::Downlink => {
                    if self.ul_seq_num == ack_num && (self.dl_seq_num == seq_num || syn) {
                        if len > 0 {
                            self.ul_seq_num = ack_num;
                            self.dl_seq_num = seq_num + len;
                        }
                        self.last_packet_status = PacketStatus::Expected;
                        return;
                    }
                }
            }

            self.last_packet_status = PacketStatus::Retransmission;
        }

        pub fn state_transition(&self) -> StateTransition {
            self.state_transition
        }

        pub fn is_handshake(&self) -> bool {
            match self.state_transition {
                SynSend | SynRecv => true,
                Established if self.prev_state_transition == SynRecv => true,
                _ => false,
            }
        }

        pub fn is_teardown(&self) -> bool {
            match self.state_transition {
                FinWait1 | FinWait2 | Closing | TimeWait => true,
                _ => false,
            }
        }

        pub fn is_last_packet_expected(&self) -> bool {
            matches!(self.last_packet_status, PacketStatus::Expected)
        }
    }
}

pub mod expression {
    use super::analyzer::TcpAnalyzer;
    use super::flow::{StateTransition, TcpFlow};
    use super::TcpClassifier;

    use crate::Config;

    use pmc_core::base::expression_value::ExpressionValue;

    use std::fmt;

    #[derive(Debug)]
    pub struct TcpSourcePort(pub u16);

    impl ExpressionValue<Config> for TcpSourcePort {
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

    impl ExpressionValue<Config> for TcpDestPort {
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

    impl ExpressionValue<Config> for TcpServerPort {
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

    impl<F> ExpressionValue<Config> for TcpPayloadLen<F>
    where
        F: Fn(u16) -> bool + 'static,
    {
        type Classifier = super::TcpClassifier;

        fn description() -> &'static str {
            "Valid if the packet payload length meets the user assert"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0(analyzer.payload_len())
        }
    }

    #[derive(Debug)]
    pub struct TcpEstablished;

    impl ExpressionValue<Config> for TcpEstablished {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the TCP flow is established"
        }

        fn check(&self, _analyzer: &TcpAnalyzer, flow: &TcpFlow) -> bool {
            StateTransition::Established == flow.state_transition()
        }
    }

    #[derive(Debug)]
    pub struct TcpHandshake;

    impl ExpressionValue<Config> for TcpHandshake {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the TCP flow is performing the handshake"
        }

        fn check(&self, _analyzer: &TcpAnalyzer, flow: &TcpFlow) -> bool {
            flow.is_handshake()
        }
    }

    #[derive(Debug)]
    pub struct TcpTeardown;

    impl ExpressionValue<Config> for TcpTeardown {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the TCP flow is performing the teardown"
        }

        fn check(&self, _analyzer: &TcpAnalyzer, flow: &TcpFlow) -> bool {
            flow.is_teardown()
        }
    }

    pub use super::analyzer::Flag as TcpFlag;

    impl ExpressionValue<Config> for TcpFlag {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the TCP packet contains the flag"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            analyzer.flags().contains(*self)
        }
    }

    #[derive(Debug)]
    pub struct TcpRetransmission;

    impl ExpressionValue<Config> for TcpRetransmission {
        type Classifier = TcpClassifier;

        fn description() -> &'static str {
            "Valid if the TCP packet is a retransmission"
        }

        fn check(&self, _analyzer: &TcpAnalyzer, flow: &TcpFlow) -> bool {
            !flow.is_last_packet_expected()
        }
    }
}
