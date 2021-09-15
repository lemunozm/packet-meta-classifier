use crate::base::config::{ClassifierId, Config};
use crate::controller::flow::{FlowController, SharedFlowController};

use std::cell::{Ref, RefMut};
use std::collections::{hash_map::Entry, HashMap};

pub struct FlowPool<C: Config> {
    flows: HashMap<C::FlowId, SharedFlowController>,
    cached: Vec<Option<SharedFlowController>>,
}

impl<C: Config> FlowPool<C> {
    pub fn new(capacity: usize) -> Self {
        Self {
            flows: HashMap::with_capacity(capacity),
            cached: (0..C::ClassifierId::TOTAL).map(|_| None).collect(),
        }
    }

    pub fn get_or_create(
        &mut self,
        id: C::ClassifierId,
        flow_id: &C::FlowId,
        builder: impl Fn() -> SharedFlowController,
    ) -> RefMut<dyn FlowController> {
        match self.flows.entry(flow_id.clone()) {
            Entry::Vacant(entry) => {
                let shared_flow = builder();
                log::trace!("Create {:?} flow. Sig: {:?}", id, flow_id);
                entry.insert(shared_flow.clone());
                self.cached[id.inner()] = Some(shared_flow.clone());
                self.cached[id.inner()].as_ref().unwrap().borrow_mut()
            }
            Entry::Occupied(entry) => {
                log::trace!("Use {:?} flow. Sig: {:?}", id, flow_id);
                self.cached[id.inner()] = Some(entry.get().clone());
                self.cached[id.inner()].as_ref().unwrap().borrow_mut()
            }
        }
    }

    pub fn get_cached(&self, id: C::ClassifierId) -> Option<Ref<dyn FlowController>> {
        self.cached[id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }

    pub fn get_cached_mut(&self, id: C::ClassifierId) -> Option<RefMut<dyn FlowController>> {
        self.cached[id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow_mut())
    }
}
