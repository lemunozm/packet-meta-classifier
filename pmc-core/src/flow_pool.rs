use crate::base::config::{ClassifierId, Config};
use crate::controller::flow::{FlowController, SharedFlowController};

use std::cell::{Ref, RefMut};
use std::collections::{hash_map::Entry, HashMap};

struct FlowInfo<V> {
    flow: SharedFlowController,
    associated_value: Option<V>,
}

impl<V> FlowInfo<V> {
    fn new(flow: SharedFlowController) -> FlowInfo<V> {
        Self {
            flow,
            associated_value: None,
        }
    }
}

pub struct FlowPool<C: Config, V> {
    flows: Vec<HashMap<C::FlowId, FlowInfo<V>>>,
    cached: Vec<Option<SharedFlowController>>,
}

impl<C: Config, V: Copy> FlowPool<C, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            flows: (0..C::ClassifierId::TOTAL)
                .map(|_| HashMap::with_capacity(capacity))
                .collect(),
            cached: (0..C::ClassifierId::TOTAL).map(|_| None).collect(),
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
                entry.insert(FlowInfo::new(shared_flow.clone()));
                self.cached[id.inner()] = Some(shared_flow);
                self.cached[id.inner()].as_ref().unwrap().borrow_mut()
            }
            Entry::Occupied(entry) => {
                log::trace!("Use {:?} flow. Sig: {:?}", id, flow_id);
                self.cached[id.inner()] = Some(entry.get().flow.clone());
                self.cached[id.inner()].as_ref().unwrap().borrow_mut()
            }
        }
    }

    pub fn get_cached(&self, id: C::ClassifierId) -> Option<Ref<dyn FlowController>> {
        self.cached[id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }

    pub fn associate_value_to_last_flow(&mut self, _value: V) {
        //TODO
    }

    pub fn delete_value_to_last_flow(&mut self) {
        //TODO
    }

    pub fn update_last_flow(&mut self) {
        //TODO
    }
}
