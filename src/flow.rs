use crate::classifiers::{Analyzer, AnalyzerId, AnalyzerStatus};

use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Hash, Clone, PartialEq, Eq)]
pub struct FlowDef {
    origin: SocketAddr,
    dest: SocketAddr,
}

pub trait GenericFlow {
    fn update(&mut self, analyzer: &dyn Analyzer);
    fn as_any(&self) -> &dyn std::any::Any;
}

#[derive(Default)]
pub struct FlowPool {
    flows: HashMap<FlowDef, Box<dyn GenericFlow>>,
}

impl FlowPool {
    pub fn get_or_create(
        &mut self,
        flow_def: FlowDef,
        flow_builder: impl FnOnce() -> Box<dyn GenericFlow>,
    ) -> &mut dyn GenericFlow {
        self.flows
            .entry(flow_def)
            .or_insert_with(flow_builder)
            .as_mut()
    }

    pub fn get(&self, flow_def: &FlowDef) -> Option<&dyn GenericFlow> {
        self.flows.get(flow_def).map(|flow| &**flow)
    }
}

pub trait Flow {
    type Analyzer: Analyzer;
    fn update(&mut self, analyzer: &Self::Analyzer);
}

#[derive(Default)]
pub struct UnusedAnalyzer;
impl Analyzer for UnusedAnalyzer {
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a> {
        unreachable!()
    }

    fn identify_flow(&self) -> Option<FlowDef> {
        unreachable!()
    }

    fn create_flow(&self) -> Box<dyn GenericFlow> {
        unreachable!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> AnalyzerId {
        AnalyzerId::None
    }
}

#[derive(Default)]
pub struct NoFlow;
impl Flow for NoFlow {
    type Analyzer = UnusedAnalyzer;
    fn update(&mut self, _analyzer: &Self::Analyzer) {
        unreachable!()
    }
}

/*
struct GenericFlowImpl<A> {}

impl<A, F> GenericValueImpl<A, F> {
    fn new(value: impl RuleValue<Analyzer = A, Flow = F> + 'static) -> Self {
        Self {
            value: Box::new(value),
        }
    }
}

impl<A: Analyzer + 'static, F: Flow + Default + 'static> GenericValue for GenericValueImpl<A, F> {
    fn check(&self, analyzer: &Box<dyn Analyzer>, flow: Option<&Box<dyn Flow>>) -> bool {
        let analyzer = (&*analyzer as &dyn std::any::Any)
            .downcast_ref::<A>()
            .unwrap();
        match flow {
            Some(flow) => {
                let flow = (&*flow as &dyn std::any::Any).downcast_ref::<F>().unwrap();
                self.value.check(analyzer, flow)
            }
            None => self.value.check(analyzer, &F::default()),
        }
    }
}
*/
