pub mod analyzer {
    use crate::classifiers::AnalyzerId;
    use crate::flow::{FlowDef, GenericFlow};
    use crate::Analyzer;

    #[derive(Default)]
    pub struct TcpAnalyzer {}

    impl Analyzer for TcpAnalyzer {
        fn analyze<'a>(&mut self, data: &'a [u8]) -> (Option<AnalyzerId>, &'a [u8]) {
            todo!()
        }

        fn identify_flow(&self) -> Option<FlowDef> {
            todo!()
        }

        fn create_flow(&self) -> Box<dyn GenericFlow> {
            todo!()
        }
    }
}

pub mod flow {
    use super::analyzer::TcpAnalyzer;

    use crate::flow::Flow;

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

    impl Flow for TcpFlow {
        type Analyzer = TcpAnalyzer;
        fn update(&mut self, analyzer: &Self::Analyzer) {}
    }
}

pub mod rules {
    use super::analyzer::TcpAnalyzer;
    use super::flow::{State, TcpFlow};

    use crate::RuleValue;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TcpState {
        Send,
        Recv,
        Established,
    }

    impl RuleValue for TcpState {
        type Flow = TcpFlow;
        type Analyzer = TcpAnalyzer;

        fn check(&self, analyzer: &Self::Analyzer, tcp_flow: &Self::Flow) -> bool {
            let tcp_state = match tcp_flow.state {
                State::Send => TcpState::Send,
                State::Recv => TcpState::Recv,
                State::Established => TcpState::Established,
            };
            tcp_state == *self
        }
    }
}
