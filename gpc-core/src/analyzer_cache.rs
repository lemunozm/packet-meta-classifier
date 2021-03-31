use crate::base::analyzer::AnalyzerResult;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::builder::GenericBuilderHandler;
use crate::packet::Packet;

pub struct AnalyzerCache<I: ClassifierId> {
    builders: Vec<Option<Box<dyn GenericBuilderHandler<I>>>>,
    life_stamp: usize,
}

impl<I: ClassifierId> AnalyzerCache<I> {
    pub fn new(builders: Vec<Option<Box<dyn GenericBuilderHandler<I>>>>) -> Self {
        Self {
            builders: builders,
            life_stamp: 1, // Must be at least 1 to be safe.
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
    ) -> AnalyzerResult<&mut dyn GenericAnalyzerHandler<I>, I> {
        self.cache.builders[id.inner()]
            .as_mut()
            .unwrap_or_else(|| panic!("The ID {:?} must be an associated builder", id))
            .build_from_packet(packet)
    }

    pub fn get(&self, id: I) -> &dyn GenericAnalyzerHandler<I> {
        self.cache.builders[id.inner()]
            .as_ref()
            .unwrap_or_else(|| panic!("The ID {:?} must be an associated builder", id))
            .get()
    }
}

impl<'a, I: ClassifierId> Drop for CacheFrame<'a, I> {
    fn drop(&mut self) {
        // Increasing the life stamp will invalidate all the references.
        self.cache.life_stamp += 1;
    }
}
