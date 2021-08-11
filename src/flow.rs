use crate::analyzer::{Analyzer, GenericAnalyzer};

use std::collections::HashMap;
use std::io::Write;

pub trait Flow {
    type Analyzer: Analyzer;
    fn create(analyzer: &Self::Analyzer) -> Self
    where
        Self: Sized;
    fn write_signature(analyzer: &Self::Analyzer, signature: impl Write)
    where
        Self: Sized;
    fn update(&mut self, analyzer: &Self::Analyzer);
}

#[derive(Default)]
pub struct NoFlow<A> {
    _analyzer: std::marker::PhantomData<A>,
}

impl<A: Analyzer> Flow for NoFlow<A> {
    type Analyzer = A;
    fn create(analyzer: &Self::Analyzer) -> Self {
        unreachable!()
    }

    fn write_signature(analyzer: &Self::Analyzer, signature: impl Write) {
        unreachable!()
    }

    fn update(&mut self, analyzer: &Self::Analyzer) {
        unreachable!()
    }
}

pub trait GenericFlow {
    fn update(&mut self, analyzer: &dyn GenericAnalyzer);
    fn as_any(&self) -> &dyn std::any::Any;
}

pub struct GenericFlowImpl<F> {
    flow: F,
}

impl<F, A> GenericFlowImpl<F>
where
    F: Flow<Analyzer = A>,
{
    pub fn new(flow: F) -> Self {
        Self { flow }
    }
}

impl<F, A> GenericFlow for GenericFlowImpl<F>
where
    F: Flow<Analyzer = A> + 'static,
    A: 'static,
{
    fn update(&mut self, analyzer: &dyn GenericAnalyzer) {
        let this_analyzer = analyzer.as_any().downcast_ref::<F::Analyzer>().unwrap();
        self.flow.update(this_analyzer);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Default)]
pub struct FlowPool {
    flows: HashMap<Vec<u8>, Box<dyn GenericFlow>>,
}

impl FlowPool {
    pub fn get_mut_or_create(
        &mut self,
        flow_signature: &[u8],
        flow_builder: impl FnOnce() -> Box<dyn GenericFlow>,
    ) -> &mut dyn GenericFlow {
        self.flows
            .entry(flow_signature.into())
            .or_insert_with(flow_builder)
            .as_mut()
    }

    pub fn get(&self, flow_signature: &[u8]) -> Option<&dyn GenericFlow> {
        self.flows.get(flow_signature).map(|flow| &**flow)
    }
}
