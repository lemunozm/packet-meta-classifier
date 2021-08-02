pub mod classifiers;
pub mod config;
pub mod engine;
pub mod flow;

use classifiers::{Analyzer, PacketInfo};
use flow::{Flow, GenericFlow};
use std::net::SocketAddr;

#[derive(Hash, Clone, PartialEq, Eq)]
enum FlowKind {
    Udp,
    Tcp,
    Http,
}

#[derive(Hash, Clone, PartialEq, Eq)]
struct FlowDef {
    origin: SocketAddr,
    dest: SocketAddr,
    kind: FlowKind,
}

enum ClassificationState<'a, T> {
    None,
    Incompleted,
    Completed(&'a Rule<T>),
}

pub struct ClassificationRules<T> {
    t: T,
}

impl<T> ClassificationRules<T> {
    fn try_classify(
        &self,
        analyzers: u64,
        packet: &PacketInfo,
        flow: Option<&dyn GenericFlow>,
    ) -> ClassificationState<T> {
        todo!()
    }
}

#[derive(Default)]
pub struct ClassificationResult<'a, T> {
    pub rule: Option<&'a Rule<T>>,
}

pub struct Rule<T> {
    t: T,
}

pub trait RuleValue: std::fmt::Debug {
    type Flow: Flow;
    type Analyzer: Analyzer;

    fn description(&self) -> String {
        todo!()
    }

    fn check(&self, analyzer: &Self::Analyzer, flow: &Self::Flow) -> bool {
        todo!()
    }
}

trait GenericValue {
    fn check(&self, analyzer: &Box<dyn Analyzer>, flow: Option<&'static dyn GenericFlow>) -> bool {
        todo!()
    }
}

struct GenericValueImpl<A, F> {
    value: Box<dyn RuleValue<Analyzer = A, Flow = F>>,
}

impl<A, F> GenericValueImpl<A, F> {
    fn new(value: impl RuleValue<Analyzer = A, Flow = F> + 'static) -> Self {
        Self {
            value: Box::new(value),
        }
    }
}

impl<A: Analyzer + 'static, F: Flow + Default + 'static> GenericValue for GenericValueImpl<A, F> {
    fn check(&self, analyzer: &Box<dyn Analyzer>, flow: Option<&'static dyn GenericFlow>) -> bool {
        let analyzer = (&*analyzer as &dyn std::any::Any)
            .downcast_ref::<A>()
            .unwrap();
        match flow {
            Some(flow) => {
                let flow = (&flow as &dyn std::any::Any).downcast_ref::<F>().unwrap();
                self.value.check(analyzer, flow)
            }
            None => self.value.check(analyzer, &F::default()),
        }
    }
}

pub struct Exp;
impl Exp {
    fn value<F: Flow + Default + 'static>(
        value: impl RuleValue<Flow = F> + 'static,
    ) -> Box<dyn GenericValue> {
        Box::new(GenericValueImpl::new(value))
    }
}
