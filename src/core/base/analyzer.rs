use super::flow::{Flow, NoFlow};
use super::id::ClassifierId;

use std::io::Write;

pub enum AnalyzerStatus<'a, I: ClassifierId> {
    Next(I, &'a [u8]),
    Finished(&'a [u8]),
    Abort,
}

pub trait Analyzer<I: ClassifierId>: Sized + Default + 'static {
    type Flow: Flow<I>;
    type PrevAnalyzer: Analyzer<I>;
    const ID: I;

    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a, I>;
    fn write_flow_signature(&self, signature: impl Write) -> bool;
}

#[derive(Default)]
pub struct NoAnalyzer;
impl<I: ClassifierId> Analyzer<I> for NoAnalyzer {
    type Flow = NoFlow<NoAnalyzer>;
    type PrevAnalyzer = Self;
    const ID: I = I::NONE;

    fn analyze<'a>(&mut self, _data: &'a [u8]) -> AnalyzerStatus<'a, I> {
        unreachable!()
    }

    fn write_flow_signature(&self, _signature: impl Write) -> bool {
        unreachable!()
    }
}
