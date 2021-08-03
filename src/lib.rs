pub mod classifiers;
pub mod config;
pub mod engine;
pub mod flow;

use classifiers::Analyzer;
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

pub enum ClassificationState<'a, T> {
    None,
    Incompleted,
    Completed(&'a Rule<T>),
}

pub struct ClassificationRules<T> {
    rules: Vec<Rule<T>>,
}

pub struct Rule<T> {
    pub exp: Exp,
    pub tag: T,
    pub priority: usize,
}

impl<T> Rule<T> {
    fn new(exp: Exp, tag: T, priority: usize) -> Self {
        Self { exp, tag, priority }
    }
}

impl<T> ClassificationRules<T> {
    pub fn new(tagged_expr: Vec<(Exp, T)>) -> ClassificationRules<T> {
        let rules = tagged_expr
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        ClassificationRules { rules }
    }

    pub fn rule(&self, priority: usize) -> Option<&Rule<T>> {
        self.rules.get(priority)
    }

    pub fn try_classify(
        &self,
        analyzers: u64,
        analyzer: &dyn Analyzer,
        flow: Option<&dyn GenericFlow>,
    ) -> ClassificationState<T> {
        for rule in &self.rules {
            if rule.exp.check(analyzer, flow) {
                return ClassificationState::Completed(rule);
            }
        }
        ClassificationState::None
    }
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

pub trait GenericValue {
    fn check(&self, analyzer: &dyn Analyzer, flow: Option<&dyn GenericFlow>) -> bool {
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
    fn check(&self, analyzer: &dyn Analyzer, flow: Option<&dyn GenericFlow>) -> bool {
        let analyzer = analyzer.as_any().downcast_ref::<A>().unwrap();
        match flow {
            Some(flow) => {
                let flow = flow.as_any().downcast_ref::<F>().unwrap();
                self.value.check(analyzer, flow)
            }
            None => self.value.check(analyzer, &F::default()),
        }
    }
}

pub enum Exp {
    Value(Box<dyn GenericValue>),
    Not(Box<Exp>),
    And(Vec<Exp>),
    Or(Vec<Exp>),
}

impl Exp {
    pub fn value<A: Analyzer + 'static, F: Flow + Default + 'static>(
        value: impl RuleValue<Analyzer = A, Flow = F> + 'static,
    ) -> Exp {
        Exp::Value(Box::new(GenericValueImpl::new(value)))
    }

    pub fn not(rule: Exp) -> Exp {
        Exp::Not(Box::new(rule))
    }

    pub fn and(expressions: Vec<Exp>) -> Exp {
        Exp::And(expressions)
    }

    pub fn or(expressions: Vec<Exp>) -> Exp {
        Exp::Or(expressions)
    }

    pub fn check(&self, analyzer: &dyn Analyzer, flow: Option<&dyn GenericFlow>) -> bool {
        match self {
            Exp::Value(value) => value.check(analyzer, flow),
            Exp::Not(rule) => !rule.check(analyzer, flow),
            Exp::And(rules) => rules.iter().all(|rule| rule.check(analyzer, flow)),
            Exp::Or(rules) => rules.iter().any(|rule| rule.check(analyzer, flow)),
        }
    }
}
