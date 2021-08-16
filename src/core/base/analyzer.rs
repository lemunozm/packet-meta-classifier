use super::flow::{Flow, NoFlow};
use super::id::ClassifierId;

use crate::core::packet::Packet;

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
    fn write_flow_signature(&self, signature: impl Write) -> bool;
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

    fn write_flow_signature(&self, _signature: impl Write) -> bool {
        unreachable!()
    }
}
