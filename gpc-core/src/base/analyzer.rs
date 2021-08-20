use crate::base::flow::{Flow, NoFlow};
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::io::Write;

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
    type Flow: Flow<I>;

    fn analyze(packet: &'a Packet) -> Option<AnalysisResult<Self, I>>;
    fn write_flow_signature(&self, signature: impl Write, direction: Direction) -> bool;
}

pub trait AnalyzerBuilder<'a, I: ClassifierId>: Sized {
    type Analyzer: Analyzer<'a, I>;
}

#[derive(Default)]
pub struct NoAnalyzer;
impl<'a, I: ClassifierId> Analyzer<'a, I> for NoAnalyzer {
    const ID: I = I::NONE;
    const PREV_ID: I = I::NONE;
    type Flow = NoFlow<NoAnalyzer>;

    fn analyze(_packet: &'a Packet) -> Option<AnalysisResult<Self, I>> {
        unreachable!()
    }

    fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
        unreachable!()
    }
}
