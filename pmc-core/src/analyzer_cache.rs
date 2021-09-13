use crate::base::analyzer::{AnalyzerResult, BuildFlow};
use crate::base::config::{ClassifierId, Config};
use crate::controller::analyzer::AnalyzerController;
use crate::controller::classifier::ClassifierController;
use crate::controller::flow::{FlowController, SharedFlowController};
use crate::packet::Packet;

pub struct AnalyzerCache<C: Config> {
    classifiers: Vec<Option<Box<dyn ClassifierController<C>>>>,
    current_ids: Vec<C::ClassifierId>,
}

impl<C: Config> AnalyzerCache<C> {
    pub fn new(classifiers: Vec<Option<Box<dyn ClassifierController<C>>>>) -> Self {
        Self {
            classifiers,
            current_ids: Vec::with_capacity(C::ClassifierId::TOTAL),
        }
    }

    pub fn prepare_for_packet(&mut self) -> CacheFrame<C> {
        CacheFrame { cache: self }
    }
}

pub struct CacheFrame<'a, C: Config> {
    cache: &'a mut AnalyzerCache<C>,
}

impl<'a, C: Config> CacheFrame<'a, C> {
    pub fn update_flow_id(
        &self,
        id: C::ClassifierId,
        flow_id: &mut C::FlowId,
        packet: &Packet,
    ) -> BuildFlow {
        self.cache.classifiers[id.inner()]
            .as_ref()
            .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
            .update_flow_id(flow_id, packet)
    }

    pub fn build_flow(&self, id: C::ClassifierId) -> SharedFlowController {
        self.cache.classifiers[id.inner()]
            .as_ref()
            .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
            .build_flow()
    }

    pub fn build_analyzer(
        &mut self,
        id: C::ClassifierId,
        config: &C,
        packet: &Packet<'a>,
        flow: Option<&dyn FlowController>,
    ) -> AnalyzerResult<&dyn AnalyzerController<'a, C>, C::ClassifierId> {
        let result = unsafe {
            // SAFETY: Cleaned before packet lifetime ends.
            self.cache.classifiers[id.inner()]
                .as_mut()
                .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                .build_analyzer(config, packet, flow)
        };

        if result.is_ok() {
            self.cache.current_ids.push(id);
        }

        result
    }

    pub fn get(&self, id: C::ClassifierId) -> &dyn AnalyzerController<'a, C> {
        unsafe {
            // SAFETY: The lifetime of the returned analyzer is the same as the lifetime with it is
            // built.
            self.cache.classifiers[id.inner()]
                .as_ref()
                .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                .get()
        }
    }

    pub fn analyzers_cached(&self) -> usize {
        self.cache.current_ids.len()
    }
}

impl<'a, C: Config> Drop for CacheFrame<'a, C> {
    fn drop(&mut self) {
        // SAFETY: Remove all the pending analyzers before packet lifetime ends.
        for id in &self.cache.current_ids {
            unsafe {
                self.cache.classifiers[id.inner()]
                    .as_mut()
                    .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                    .clean();
            }
        }
        self.cache.current_ids.clear();
    }
}
