use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

pub trait Analyzer<'a, I: ClassifierId>: Sized {
    const ID: I;
    const PREV_ID: I;

    type Flow: Default + 'static;

    fn build(packet: &'a Packet) -> AnalyzerResult<Self, I>;

    fn update_flow_id(&self, _flow_id: &mut I::FlowId, _direction: Direction) -> bool {
        false
    }

    fn update_flow(&self, _flow: &mut Self::Flow, _direction: Direction) {
        unimplemented!("Analyzer {:?} do not update the flow instance", Self::ID)
    }
}

pub type AnalyzerResult<A, I> = Result<AnalyzerInfo<A, I>, &'static str>;

pub struct AnalyzerInfo<A, I: ClassifierId> {
    pub analyzer: A,
    pub next_classifier_id: I,
    pub bytes_parsed: usize,
}
