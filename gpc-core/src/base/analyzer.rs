use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::io::Write;

//TODO: rename AnalyzerInfo?
pub struct AnalysisResult<A, I>
where
    I: ClassifierId,
{
    pub analyzer: A,
    pub next_id: I,
    pub bytes: usize, //TODO: rename: bytes_parsed
}

pub trait Analyzer<'a, I: ClassifierId>: Sized {
    const ID: I;
    const PREV_ID: I;
    type Flow: Flow<Self, I>;

    fn analyze(packet: &Packet<'a>) -> Option<AnalysisResult<Self, I>>; //TODO: packet inside lifetime
    fn write_flow_signature(&self, signature: impl Write, direction: Direction) -> bool;
}

pub trait AnalyzerBuilder<'a, I: ClassifierId>: Sized {
    type Analyzer: Analyzer<'a, I>;
}
