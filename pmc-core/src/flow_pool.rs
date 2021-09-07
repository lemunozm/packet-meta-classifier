use crate::base::id::ClassifierId;
use crate::controller::analyzer::AnalyzerController;
use crate::controller::flow::{FlowController, SharedFlowController};
use crate::packet::Direction;

use std::cell::Ref;
use std::collections::{hash_map::Entry, HashMap};

pub struct FlowPool<I, T>
where
    I: ClassifierId,
{
    flows: Vec<HashMap<I::FlowId, (SharedFlowController, Option<T>)>>,
    flow_cache: Vec<Option<SharedFlowController>>,
    current_flow_id: I::FlowId,
}

impl<I: ClassifierId, T> Default for FlowPool<I, T> {
    fn default() -> Self {
        Self {
            flows: (0..I::TOTAL).map(|_| HashMap::default()).collect(),
            flow_cache: (0..I::TOTAL).map(|_| None).collect(),
            current_flow_id: I::FlowId::default(),
        }
    }
}

impl<I: ClassifierId, T: Copy> FlowPool<I, T> {
    pub fn prepare_for_packet(&mut self) {
        self.current_flow_id = I::FlowId::default();
    }

    pub fn update(
        &mut self,
        analyzer: &dyn AnalyzerController<I>,
        direction: Direction,
    ) -> Option<T> {
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
                    analyzer.update_flow(&mut *shared_flow.borrow_mut(), direction);
                    entry.insert((shared_flow.clone(), None));
                    self.flow_cache[analyzer.id().inner()] = Some(shared_flow);
                }
                Entry::Occupied(mut entry) => {
                    if let Some(tag) = &entry.get_mut().1 {
                        return Some(*tag);
                    }
                    analyzer.update_flow(&mut *entry.get_mut().0.borrow_mut(), direction);
                }
            }
        } else {
            self.flow_cache[analyzer.id().inner()] = None;
        }
        None
    }

    pub fn get_cached(&self, classifier_id: I) -> Option<Ref<dyn FlowController>> {
        self.flow_cache[classifier_id.inner()]
            .as_ref()
            .map(|shared_flow| shared_flow.borrow())
    }

    pub fn associate_tag_to_last_flow(&mut self, _tag: T) {
        //TODO
    }
}
