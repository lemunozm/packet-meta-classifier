use crate::base::flow::{Flow, NoFlow};
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::io::Write;

pub type AnalyzerResult<A, I> = Result<AnalyzerInfo<A, I>, &'static str>;

pub struct AnalyzerInfo<A, I: ClassifierId> {
    pub analyzer: A,
    pub next_classifier_id: I,
    pub bytes_parsed: usize,
}

pub trait Analyzer<I: ClassifierId>: Sized {
    //TODO: PERF: Use 'a lifetime that be less than the packet data.
    const ID: I;
    const PREV_ID: I;
    type Flow: Flow<Self>;

    fn build(packet: &Packet) -> AnalyzerResult<Self, I>;
    fn write_flow_signature(&self, signature: impl Write, direction: Direction) -> bool;
}

#[derive(Default)]
pub struct NoAnalyzer;
impl<I: ClassifierId> Analyzer<I> for NoAnalyzer {
    const ID: I = I::NONE;
    const PREV_ID: I = I::NONE;
    type Flow = NoFlow;

    fn build(_packet: &Packet) -> AnalyzerResult<NoAnalyzer, I> {
        unreachable!()
    }

    fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
        unreachable!()
    }
}
