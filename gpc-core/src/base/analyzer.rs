use crate::base::flow::{Flow, NoFlow};
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::io::Write;

pub enum AnalyzerStatus<I: ClassifierId> {
    Next(I, usize),
    Abort,
}

impl<I: ClassifierId> AnalyzerStatus<I> {
    pub fn next(self) -> (I, usize) {
        match self {
            Self::Next(classifier_id, bytes_parsed) => (classifier_id, bytes_parsed),
            Self::Abort => panic!("Expected Next variant"),
        }
    }
}

pub trait Analyzer<I: ClassifierId>: Sized + Default + 'static {
    //TODO: PERF: Use 'a lifetime that be less than the packet data.
    const ID: I;
    const PREV_ID: I;
    type Flow: Flow<I>;

    fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<I>;
    fn write_flow_signature(&self, signature: impl Write, direction: Direction) -> bool;
}

#[derive(Default)]
pub struct NoAnalyzer;
impl<I: ClassifierId> Analyzer<I> for NoAnalyzer {
    const ID: I = I::NONE;
    const PREV_ID: I = I::NONE;
    type Flow = NoFlow<NoAnalyzer>;

    fn analyze<'a>(&mut self, _packet: &Packet) -> AnalyzerStatus<I> {
        unreachable!()
    }

    fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
        unreachable!()
    }
}
