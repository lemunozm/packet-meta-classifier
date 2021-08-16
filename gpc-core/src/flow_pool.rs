use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::flow::GenericFlowHandler;
use crate::packet::Direction;

use std::cell::{Ref, RefCell};
use std::collections::{hash_map::Entry, HashMap};
use std::rc::Rc;

pub struct FlowPool<I> {
    flows: Vec<HashMap<Vec<u8>, Rc<RefCell<dyn GenericFlowHandler<I>>>>>,
    flow_cache: Vec<Option<Rc<RefCell<dyn GenericFlowHandler<I>>>>>,
    current_flow_signature: Vec<u8>,
}

impl<I: ClassifierId> FlowPool<I> {
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

    pub fn update(&mut self, analyzer: &dyn GenericAnalyzerHandler<I>, direction: Direction) {
        if analyzer.update_flow_signature(&mut self.current_flow_signature, direction) {
            //IDEA: The vec alloc could be avoided using an array in FlowPool?
            let entry =
                self.flows[analyzer.id().inner()].entry(self.current_flow_signature.clone());

            log::trace!(
                "{} {:?} flow. Sig: {:?}",
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
                    let shared_flow = analyzer.create_flow(direction);
                    entry.insert(shared_flow.clone());
                    self.flow_cache[analyzer.id().inner()] = Some(shared_flow);
                }
                Entry::Occupied(mut entry) => {
                    entry.get_mut().borrow_mut().update(analyzer, direction);
                }
            }
        } else {
            self.flow_cache[analyzer.id().inner()] = None;
        }
    }

    pub fn get_cached(&self, classifier_id: I) -> Option<Ref<dyn GenericFlowHandler<I>>> {
        self.flow_cache[classifier_id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }
}
