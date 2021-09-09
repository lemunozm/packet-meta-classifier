use crate::base::config::{ClassifierId, Config};
use crate::controller::analyzer::AnalyzerController;
use crate::controller::flow::{FlowController, SharedFlowController};
use crate::packet::Direction;

use std::cell::Ref;
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
    flow_cache: Vec<Option<SharedFlowController>>,
    current_flow_id: C::FlowId,
}

impl<C: Config, V: Copy> FlowPool<C, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            flows: (0..C::ClassifierId::TOTAL)
                .map(|_| HashMap::with_capacity(capacity))
                .collect(),
            flow_cache: (0..C::ClassifierId::TOTAL).map(|_| None).collect(),
            current_flow_id: C::FlowId::default(),
        }
    }

    pub fn prepare_for_packet(&mut self) {
        self.current_flow_id = C::FlowId::default();
    }

    pub fn update(
        &mut self,
        config: &C,
        analyzer: &dyn AnalyzerController<C>,
        direction: Direction,
    ) -> Option<V> {
        if analyzer.update_flow_id(&mut self.current_flow_id, direction) {
            let entry = self.flows[analyzer.id().inner()].entry(self.current_flow_id.clone());

            log::trace!(
                "Use {:?} flow. Sig: {:?}",
                analyzer.id(),
                self.current_flow_id,
            );

            match entry {
                Entry::Vacant(entry) => {
                    let shared_flow = analyzer.create_flow();
                    analyzer.update_flow(config, &mut *shared_flow.borrow_mut(), direction);
                    entry.insert(FlowInfo::new(shared_flow.clone()));
                    self.flow_cache[analyzer.id().inner()] = Some(shared_flow);
                }
                Entry::Occupied(mut entry) => {
                    if let Some(value) = &entry.get_mut().associated_value {
                        return Some(*value);
                    }
                    analyzer.update_flow(
                        config,
                        &mut *entry.get_mut().flow.borrow_mut(),
                        direction,
                    );
                }
            }
        } else {
            self.flow_cache[analyzer.id().inner()] = None;
        }
        None
    }

    pub fn get_cached(&self, id: C::ClassifierId) -> Option<Ref<dyn FlowController>> {
        self.flow_cache[id.inner()]
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
