use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::flow::{GenericFlowHandler, SharedGenericFlowHandler};
use crate::packet::Direction;

use std::cell::Ref;
use std::collections::{hash_map::Entry, HashMap};
use std::marker::PhantomData;

pub struct FlowPool<I: ClassifierId> {
    flows: Vec<HashMap<I::FlowId, SharedGenericFlowHandler>>,
    flow_cache: Vec<Option<SharedGenericFlowHandler>>,
    current_flow_id: I::FlowId,
    _id: PhantomData<I>,
}

impl<I: ClassifierId> Default for FlowPool<I> {
    fn default() -> Self {
        Self {
            flows: (0..I::TOTAL).map(|_| HashMap::default()).collect(),
            flow_cache: (0..I::TOTAL).map(|_| None).collect(),
            current_flow_id: I::FlowId::default(),
            _id: PhantomData::default(),
        }
    }
}

impl<I: ClassifierId> FlowPool<I> {
    pub fn prepare_for_packet(&mut self) {
        self.current_flow_id = I::FlowId::default();
    }

    pub fn update(&mut self, analyzer: &dyn GenericAnalyzerHandler<I>, direction: Direction) {
        if analyzer.update_flow_id(&mut self.current_flow_id, direction) {
            let entry = self.flows[analyzer.id().inner()].entry(self.current_flow_id.clone());

            log::trace!(
                "{} {:?} flow. Sig: {:?}",
                if let Entry::Vacant(_) = entry {
                    "Create"
                } else {
                    "Update"
                },
                analyzer.id(),
                self.current_flow_id,
            );

            match entry {
                Entry::Vacant(entry) => {
                    let shared_flow = analyzer.create_flow(direction);
                    entry.insert(shared_flow.clone());
                    self.flow_cache[analyzer.id().inner()] = Some(shared_flow);
                }
                Entry::Occupied(mut entry) => {
                    analyzer.update_flow(&mut *entry.get_mut().borrow_mut(), direction);
                }
            }
        } else {
            self.flow_cache[analyzer.id().inner()] = None;
        }
    }

    pub fn get_cached(&self, classifier_id: I) -> Option<Ref<dyn GenericFlowHandler>> {
        self.flow_cache[classifier_id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }
}
