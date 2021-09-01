use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::io::Write;

pub type AnalyzerResult<A, I> = Result<AnalyzerInfo<A, I>, &'static str>;

pub struct AnalyzerInfo<A, I: ClassifierId> {
    pub analyzer: A,
    pub next_classifier_id: I,
    pub bytes_parsed: usize,
}

pub trait Analyzer<'a, I: ClassifierId>: Sized {
    const ID: I;
    const PREV_ID: I;

    fn build(packet: &'a Packet) -> AnalyzerResult<Self, I>;
    fn write_flow_signature(&self, signature: impl Write, direction: Direction) -> bool;
}
