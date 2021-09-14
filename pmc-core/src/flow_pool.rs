use crate::base::config::{ClassifierId, Config};
use crate::controller::flow::{FlowController, SharedFlowController};

use std::cell::{Ref, RefMut};
use std::collections::{hash_map::Entry, HashMap};

pub struct FlowPool<C: Config> {
    flows: Vec<HashMap<C::FlowId, SharedFlowController>>,
    cached: Vec<Option<SharedFlowController>>,
    last_cache_index: Option<usize>,
}

impl<C: Config> FlowPool<C> {
    pub fn new(capacity: usize) -> Self {
        Self {
            flows: (0..C::ClassifierId::TOTAL)
                .map(|_| HashMap::with_capacity(capacity))
                .collect(),
            cached: (0..C::ClassifierId::TOTAL).map(|_| None).collect(),
            last_cache_index: None,
        }
    }

    pub fn get_or_create(
        &mut self,
        id: C::ClassifierId,
        flow_id: &C::FlowId,
        builder: impl Fn() -> SharedFlowController,
    ) -> RefMut<dyn FlowController> {
        match self.flows[id.inner()].entry(flow_id.clone()) {
            Entry::Vacant(entry) => {
                let shared_flow = builder();
                log::trace!("Create {:?} flow. Sig: {:?}", id, flow_id);
                entry.insert(shared_flow.clone());
                self.cached[id.inner()] = Some(shared_flow.clone());
                self.last_cache_index = Some(id.inner());
                self.cached[id.inner()].as_ref().unwrap().borrow_mut()
            }
            Entry::Occupied(entry) => {
                log::trace!("Use {:?} flow. Sig: {:?}", id, flow_id);
                self.cached[id.inner()] = Some(entry.get().clone());
                self.last_cache_index = Some(id.inner());
                self.cached[id.inner()].as_ref().unwrap().borrow_mut()
            }
        }
    }

    pub fn get_cached(&self, id: C::ClassifierId) -> Option<Ref<dyn FlowController>> {
        self.cached[id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }

    pub fn last_flow(&mut self) -> RefMut<dyn FlowController> {
        self.cached[self.last_cache_index.unwrap()]
            .as_ref()
            .unwrap()
            .borrow_mut()
    }
}
