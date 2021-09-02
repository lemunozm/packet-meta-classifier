use crate::base::analyzer::AnalyzerResult;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::builder::GenericBuilderHandler;
use crate::packet::Packet;

pub struct AnalyzerCache<I: ClassifierId> {
    builders: Vec<Option<Box<dyn GenericBuilderHandler<I>>>>,
    current_ids: Vec<I>,
}

impl<I: ClassifierId> AnalyzerCache<I> {
    pub fn new(builders: Vec<Option<Box<dyn GenericBuilderHandler<I>>>>) -> Self {
        Self {
            builders: builders,
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
    pub fn build_from_packet(
        &mut self,
        id: I,
        packet: &Packet<'a>,
    ) -> AnalyzerResult<&dyn GenericAnalyzerHandler<'a, I>, I> {
        /*
        let result = unsafe {
            // SAFETY: Cleaned before packet lifetime ends.
            self.cache.builders[id.inner()]
                .as_mut()
                .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                .build_from_packet(packet)
        };

        if result.is_ok() {
            self.cache.current_ids.push(id);
        }

        result
        */
        todo!()
    }

    pub fn get(&self, id: I) -> &dyn GenericAnalyzerHandler<'a, I> {
        /*
        unsafe {
            // SAFETY: The lifetime of the returned analyzer is the same as the  lifetime.
            self.cache.builders[id.inner()]
                .as_ref()
                .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                .get()
        }
        */
        todo!()
    }
}

impl<'a, I: ClassifierId> Drop for CacheFrame<'a, I> {
    fn drop(&mut self) {
        /*
        // SAFETY: Remove all the pending analyzers before packet lifetime ends.
        for id in &self.cache.current_ids {
            unsafe {
                self.cache.builders[id.inner()]
                    .as_mut()
                    .unwrap_or_else(|| panic!("The ID {:?} must have an associated builder", id))
                    .clean();
            }
        }
        self.cache.current_ids.clear();
        */
        todo!()
    }
}
