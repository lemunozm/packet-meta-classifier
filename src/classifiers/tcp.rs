pub mod flow {
    use crate::Flow;
    pub enum State {
        Send,
        Recv,
        Established,
    }

    impl Default for State {
        fn default() -> Self {
            State::Send
        }
    }

    #[derive(Default)]
    pub struct TcpFlow {
        pub state: State,
    }
    impl Flow for TcpFlow {}
}

pub mod analyzer {
    use crate::classifiers::AnalyzerKind;
    use crate::Analyzer;

    #[derive(Default)]
    pub struct TcpPacket {}
    impl Analyzer for TcpPacket {
        fn analyze<'a>(&mut self, data: &'a [u8]) -> (Option<AnalyzerKind>, &'a [u8]) {
            todo!()
        }
    }
}

pub mod rules {
    use super::flow::{State, TcpFlow};

    use crate::PacketInfo;
    use crate::RuleValue;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TcpState {
        Send,
        Recv,
        Established,
    }

    impl From<&State> for TcpState {
        fn from(state: &State) -> TcpState {
            match state {
                State::Send => Self::Send,
                State::Recv => Self::Recv,
                State::Established => Self::Established,
            }
        }
    }

    impl RuleValue for TcpState {
        type Flow = TcpFlow;

        fn check(&self, packet: &PacketInfo, tcp_flow: &Self::Flow) -> bool {
            TcpState::from(&tcp_flow.state) == *self
        }
    }
}
