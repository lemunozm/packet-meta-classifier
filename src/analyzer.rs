use crate::classifier::id::ClassifierIdTrait;
use crate::flow::{Flow, GenericFlow, GenericFlowImpl, NoFlow};

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

pub enum AnalyzerStatus<'a, I: ClassifierIdTrait> {
    Next(I, &'a [u8]),
    Finished(&'a [u8]),
    Abort,
}

pub trait Analyzer<I: ClassifierIdTrait>: Sized + Default {
    type Flow: Flow<I>;
    type PrevAnalyzer: Analyzer<I>;
    const ID: I;

    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a, I>;
    fn write_flow_signature(&self, signature: impl Write) -> bool;
}

#[derive(Default)]
pub struct NoAnalyzer;
impl<I: ClassifierIdTrait> Analyzer<I> for NoAnalyzer {
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

pub trait GenericAnalyzer<I: ClassifierIdTrait> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a, I>;
    fn as_any(&self) -> &dyn std::any::Any;
    fn reset(&mut self);
    fn update_flow_signature(&self, current_signature: &mut Vec<u8>) -> bool;
    fn create_flow(&self) -> Rc<RefCell<dyn GenericFlow<I>>>;
}

pub struct GenericAnalyzerImpl<A> {
    analyzer: A,
}

impl<A> GenericAnalyzerImpl<A> {
    pub fn new(analyzer: A) -> Self {
        Self { analyzer }
    }

    pub fn analyzer(&self) -> &A {
        &self.analyzer
    }
}

impl<A, F, I> GenericAnalyzer<I> for GenericAnalyzerImpl<A>
where
    A: Analyzer<I, Flow = F> + 'static,
    F: Flow<I, Analyzer = A> + 'static,
    I: ClassifierIdTrait,
{
    fn id(&self) -> I {
        A::ID
    }

    fn prev_id(&self) -> I {
        A::PrevAnalyzer::ID
    }

    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a, I> {
        self.analyzer.analyze(data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn reset(&mut self) {
        self.analyzer = A::default();
    }

    fn update_flow_signature(&self, mut current_signature: &mut Vec<u8>) -> bool {
        self.analyzer.write_flow_signature(&mut current_signature)
    }

    fn create_flow(&self) -> Rc<RefCell<dyn GenericFlow<I>>> {
        Rc::new(RefCell::new(GenericFlowImpl::new(F::create(
            &self.analyzer,
        ))))
    }
}
