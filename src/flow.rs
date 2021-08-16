use crate::analyzer::{Analyzer, GenericAnalyzer, GenericAnalyzerImpl};
use crate::classifier::id::ClassifierIdTrait;

use std::cell::{Ref, RefCell};
use std::collections::{hash_map::Entry, HashMap};
use std::fmt;
use std::rc::Rc;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    Uplink,
    Downlink,
}

impl From<bool> for Direction {
    fn from(value: bool) -> Self {
        match value {
            true => Self::Uplink,
            false => Self::Downlink,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uplink => write!(f, "uplink"),
            Self::Downlink => write!(f, "downlink"),
        }
    }
}

pub trait Flow<I: ClassifierIdTrait> {
    type Analyzer: Analyzer<I>;
    fn create(analyzer: &Self::Analyzer) -> Self;
    fn update(&mut self, analyzer: &Self::Analyzer);
}

pub struct NoFlow<A> {
    _analyzer: std::marker::PhantomData<A>,
}

impl<A: Analyzer<I>, I: ClassifierIdTrait> Flow<I> for NoFlow<A> {
    type Analyzer = A;
    fn create(_analyzer: &Self::Analyzer) -> Self {
        NoFlow {
            _analyzer: std::marker::PhantomData::default(),
        }
    }

    fn update(&mut self, _analyzer: &Self::Analyzer) {
        unreachable!()
    }
}

pub trait GenericFlow<I> {
    fn update(&mut self, analyzer: &dyn GenericAnalyzer<I>);
    fn as_any(&self) -> &dyn std::any::Any;
}

pub struct GenericFlowImpl<F, I> {
    flow: F,
    _classify_type: std::marker::PhantomData<I>,
}

impl<F, A, I> GenericFlowImpl<F, I>
where
    F: Flow<I, Analyzer = A>,
    A: 'static,
    I: ClassifierIdTrait,
{
    pub fn new(flow: F) -> Self {
        Self {
            flow,
            _classify_type: std::marker::PhantomData::default(),
        }
    }

    pub fn flow(&self) -> &F {
        &self.flow
    }
}

impl<F, A, I> GenericFlow<I> for GenericFlowImpl<F, I>
where
    F: Flow<I, Analyzer = A> + 'static,
    A: 'static,
    I: ClassifierIdTrait,
{
    fn update(&mut self, analyzer: &dyn GenericAnalyzer<I>) {
        let this_analyzer = analyzer
            .as_any()
            .downcast_ref::<GenericAnalyzerImpl<F::Analyzer>>()
            .unwrap()
            .analyzer();

        self.flow.update(this_analyzer);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct FlowPool<I> {
    flows: Vec<HashMap<Vec<u8>, Rc<RefCell<dyn GenericFlow<I>>>>>,
    flow_cache: Vec<Option<Rc<RefCell<dyn GenericFlow<I>>>>>,
    current_flow_signature: Vec<u8>,
}

impl<I: ClassifierIdTrait> FlowPool<I> {
    pub fn new() -> Self {
        Self {
            flows: (0..I::TOTAL).map(|_| HashMap::default()).collect(),

            flow_cache: (0..I::TOTAL).map(|_| None).collect(),
            current_flow_signature: Vec::with_capacity(64),
        }
    }

    pub fn prepare_for_packet(&mut self) {
        self.current_flow_signature.clear();
    }

    pub fn update(&mut self, analyzer: &dyn GenericAnalyzer<I>, _direction: Direction) {
        if analyzer.update_flow_signature(&mut self.current_flow_signature) {
            //IDEA: The vec alloc could be avoided using an array in FlowPool?
            let entry =
                self.flows[analyzer.id().inner()].entry(self.current_flow_signature.clone());

            log::trace!(
                "{} flow {:?}. Sig: {:?}",
                if let Entry::Vacant(_) = entry {
                    "Create"
                } else {
                    "Update"
                },
                analyzer.id(),
                self.current_flow_signature,
            );

            match entry {
                Entry::Vacant(entry) => {
                    let shared_flow = analyzer.create_flow();
                    entry.insert(shared_flow.clone());
                    self.flow_cache[analyzer.id().inner()] = Some(shared_flow);
                }
                Entry::Occupied(mut entry) => {
                    entry.get_mut().borrow_mut().update(analyzer);
                }
            }
        } else {
            self.flow_cache[analyzer.id().inner()] = None;
        }
    }

    pub fn get_cached(&self, classifier_id: I) -> Option<Ref<dyn GenericFlow<I>>> {
        self.flow_cache[classifier_id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }
}
