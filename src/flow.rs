use crate::analyzer::{Analyzer, GenericAnalyzer, GenericAnalyzerImpl};
use crate::classifiers::ClassifierId;

use std::cell::{Ref, RefCell};
use std::collections::{hash_map::Entry, HashMap};
use std::rc::Rc;

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

    pub fn flow(&self) -> &F {
        &self.flow
    }
}

impl<F, A> GenericFlow for GenericFlowImpl<F>
where
    F: Flow<Analyzer = A> + 'static,
    A: 'static,
{
    fn update(&mut self, analyzer: &dyn GenericAnalyzer) {
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

pub struct FlowPool {
    flows: Vec<HashMap<Vec<u8>, Rc<RefCell<dyn GenericFlow>>>>,
    flow_cache: Vec<Option<Rc<RefCell<dyn GenericFlow>>>>,
    current_flow_signature: Vec<u8>,
}

impl Default for FlowPool {
    fn default() -> Self {
        Self {
            flows: (0..ClassifierId::COUNT)
                .map(|_| HashMap::default())
                .collect(),

            flow_cache: (0..ClassifierId::COUNT).map(|_| None).collect(),
            current_flow_signature: Vec::with_capacity(16),
        }
    }
}

impl FlowPool {
    pub fn prepare_for_packet(&mut self) {
        self.current_flow_signature.clear();
    }

    pub fn update(&mut self, analyzer: &dyn GenericAnalyzer) {
        if analyzer.update_flow_signature(&mut self.current_flow_signature) {
            //IDEA: The vec alloc could be avoided using an array in FlowPool?
            let entry =
                self.flows[analyzer.id() as usize].entry(self.current_flow_signature.clone());

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
                    self.flow_cache[analyzer.id() as usize] = Some(shared_flow);
                }
                Entry::Occupied(mut entry) => {
                    entry.get_mut().borrow_mut().update(analyzer);
                }
            }
        } else {
            self.flow_cache[analyzer.id() as usize] = None;
        }
    }

    pub fn get_cached(&self, classifier_id: ClassifierId) -> Option<Ref<dyn GenericFlow>> {
        self.flow_cache[classifier_id as usize]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }
}
