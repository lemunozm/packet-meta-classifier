use crate::classifiers::Analyzer;

use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Hash, Clone, PartialEq, Eq)]
enum FlowKind {
    Udp,
    Tcp,
    Http,
}

#[derive(Hash, Clone, PartialEq, Eq)]
pub struct FlowDef {
    origin: SocketAddr,
    dest: SocketAddr,
    kind: FlowKind,
}

pub trait GenericFlow {
    fn update(&mut self, analyzer: &dyn Analyzer) {
        todo!()
    }

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
}

pub trait Flow {
    type Analyzer: Analyzer;
    fn update(&mut self, analyzer: &Self::Analyzer) {}
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
