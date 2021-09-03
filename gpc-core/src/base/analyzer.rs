use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::io::Write;

pub trait Analyzer<'a, I: ClassifierId>: Sized {
    const ID: I;
    const PREV_ID: I;

    type Flow: Sized + 'static;

    fn build(packet: &'a Packet) -> AnalyzerResult<Self, I>;
    fn write_flow_signature(&self, signature: impl Write, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> Self::Flow {
        unimplemented!()
    }
    fn update_flow(&self, flow: &mut Self::Flow, direction: Direction) {
        unimplemented!()
    }
}

pub type AnalyzerResult<A, I> = Result<AnalyzerInfo<A, I>, &'static str>;

pub struct AnalyzerInfo<A, I: ClassifierId> {
    pub analyzer: A,
    pub next_classifier_id: I,
    pub bytes_parsed: usize,
}
