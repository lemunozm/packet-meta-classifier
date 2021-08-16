use crate::base::flow::{Flow, NoFlow};
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::io::Write;

pub enum AnalyzerStatus<I: ClassifierId> {
    Next(I, usize),
    Finished(usize),
    Abort,
}

pub trait Analyzer<I: ClassifierId>: Sized + Default + 'static {
    type Flow: Flow<I>;
    type PrevAnalyzer: Analyzer<I>;
    const ID: I;

    fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<I>;
    fn write_flow_signature(&self, signature: impl Write, direction: Direction) -> bool;
}

#[derive(Default)]
pub struct NoAnalyzer;
impl<I: ClassifierId> Analyzer<I> for NoAnalyzer {
    type Flow = NoFlow<NoAnalyzer>;
    type PrevAnalyzer = Self;
    const ID: I = I::NONE;

    fn analyze<'a>(&mut self, _packet: &Packet) -> AnalyzerStatus<I> {
        unreachable!()
    }

    fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
        unreachable!()
    }
}
