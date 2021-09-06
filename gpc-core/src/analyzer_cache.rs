use crate::base::analyzer::AnalyzerResult;
use crate::base::id::ClassifierId;
use crate::controller::analyzer::AnalyzerController;
use crate::controller::classifier::ClassifierController;
use crate::packet::Packet;

pub struct AnalyzerCache<I: ClassifierId> {
    classifiers: Vec<Option<Box<dyn ClassifierController<I>>>>,
    current_ids: Vec<I>,
}

impl<I: ClassifierId> AnalyzerCache<I> {
    pub fn new(classifiers: Vec<Option<Box<dyn ClassifierController<I>>>>) -> Self {
        Self {
            classifiers,
            current_ids: Vec::with_capacity(I::TOTAL),
        }
    }

    pub fn prepare_for_packet(&mut self) -> CacheFrame<I> {
        CacheFrame { cache: self }
    }
}

pub struct CacheFrame<'a, I: ClassifierId> {
    cache: &'a mut AnalyzerCache<I>,
}

impl<'a, I: ClassifierId> CacheFrame<'a, I> {
    pub fn build_analyzer(
        &mut self,
        id: I,
        packet: &Packet<'a>,
    ) -> AnalyzerResult<&dyn AnalyzerController<'a, I>, I> {
        let result = unsafe {
            // SAFETY: Cleaned before packet lifetime ends.
            self.cache.classifiers[id.inner()]
                .as_mut()
                .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                .build_analyzer(packet)
        };

        if result.is_ok() {
            self.cache.current_ids.push(id);
        }

        result
    }

    pub fn get(&self, id: I) -> &dyn AnalyzerController<'a, I> {
        unsafe {
            // SAFETY: The lifetime of the returned analyzer is the same as the lifetime with it is
            // built.
            self.cache.classifiers[id.inner()]
                .as_ref()
                .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                .get()
        }
    }
}

impl<'a, I: ClassifierId> Drop for CacheFrame<'a, I> {
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
