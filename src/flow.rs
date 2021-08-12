use crate::analyzer::{Analyzer, GenericAnalyzer};
use crate::classifiers::ClassifierId;

use std::collections::HashMap;

use strum::EnumCount;

pub trait Flow {
    type Analyzer: Analyzer;
    fn create(analyzer: &Self::Analyzer) -> Self;
    fn update(&mut self, analyzer: &Self::Analyzer);
}

pub struct NoFlow<A> {
    _analyzer: std::marker::PhantomData<A>,
}

impl<A: Analyzer> Flow for NoFlow<A> {
    type Analyzer = A;
    fn create(_analyzer: &Self::Analyzer) -> Self {
        unreachable!()
    }

    fn update(&mut self, _analyzer: &Self::Analyzer) {
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

pub struct FlowPool {
    flows: Vec<HashMap<Vec<u8>, Box<dyn GenericFlow>>>,
}

impl Default for FlowPool {
    fn default() -> Self {
        Self {
            flows: (0..ClassifierId::COUNT)
                .map(|_| HashMap::default())
                .collect(),
        }
    }
}

impl FlowPool {
    pub fn get_mut_or_create(
        &mut self,
        classifier_id: ClassifierId,
        flow_signature: &[u8],
        flow_builder: impl FnOnce() -> Box<dyn GenericFlow>,
    ) -> &mut dyn GenericFlow {
        self.flows[classifier_id as usize]
            .entry(flow_signature.into())
            .or_insert_with(flow_builder)
            .as_mut()
    }

    pub fn get(
        &self,
        classifier_id: ClassifierId,
        flow_signature: &[u8],
    ) -> Option<&dyn GenericFlow> {
        self.flows[classifier_id as usize]
            .get(flow_signature)
            .map(|flow| &**flow)
    }
}
