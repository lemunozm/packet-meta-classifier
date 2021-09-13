use crate::base::config::{ClassifierId, Config};

use crate::packet::{Direction, Packet};

pub enum BuildFlow {
    Yes,
    No,
    Abort(&'static str),
}

pub trait Analyzer<'a, C: Config>: Sized {
    const ID: C::ClassifierId;
    const PREV_ID: C::ClassifierId;

    type Flow: Default + 'static;

    fn update_flow_id(_flow_id: &mut C::FlowId, _packet: &Packet) -> BuildFlow {
        BuildFlow::No
    }

    fn build(
        config: &C,
        packet: &'a Packet,
        flow: &Self::Flow,
    ) -> AnalyzerResult<Self, C::ClassifierId>;

    fn update_flow(&self, _config: &C, _flow: &mut Self::Flow, _direction: Direction) {
        unimplemented!("Analyzer {:?} do not update the flow instance", Self::ID)
    }
}

pub type AnalyzerResult<A, I> = Result<AnalyzerInfo<A, I>, &'static str>;

pub struct AnalyzerInfo<A, I: ClassifierId> {
    pub analyzer: A,
    pub next_classifier_id: I,
    pub bytes_parsed: usize,
}
