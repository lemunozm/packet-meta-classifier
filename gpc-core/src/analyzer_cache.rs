use crate::base::analyzer::{AnalysisResult, Analyzer, AnalyzerBuilder};
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};
use crate::packet::Packet;

use std::mem::MaybeUninit;

pub trait GenericAnalyzerBuilder<I: ClassifierId> {
    fn build_from_packet<'a>(
        &mut self,
        packet: &Packet<'a>,
        life_stamp: usize,
    ) -> Option<AnalysisResult<&dyn GenericAnalyzerHandler<'a, I>, I>>;

    unsafe fn get<'a>(&self, life_stamp: usize) -> Option<&dyn GenericAnalyzerHandler<'a, I>>;
}

pub struct AnalyzerBuilderHandler<'a, I, B>
where
    B: AnalyzerBuilder<'a, I>,
    I: ClassifierId,
{
    analyzer_mem: MaybeUninit<AnalyzerHandler<B::Analyzer>>,
    life_stamp: usize,
}

impl<'a, I, B> AnalyzerBuilderHandler<'a, I, B>
where
    B: for<'e> AnalyzerBuilder<'e, I> + 'static,
    I: ClassifierId,
{
    pub fn new() -> Self {
        Self {
            analyzer_mem: std::mem::MaybeUninit::uninit(),
            life_stamp: 0,
        }
    }
}

impl<'a, I, B, F, A> GenericAnalyzerBuilder<I> for AnalyzerBuilderHandler<'a, I, B>
where
    B: for<'b> AnalyzerBuilder<'b, I, Analyzer = A> + 'static,
    A: for<'b> Analyzer<'b, I, Flow = F>,
    F: Flow<I, Analyzer = A> + 'static,
    I: ClassifierId,
{
    fn build_from_packet<'c>(
        &mut self,
        packet: &Packet<'c>,
        life_stamp: usize,
    ) -> Option<AnalysisResult<&dyn GenericAnalyzerHandler<'c, I>, I>> {
        AnalyzerHandler::<B::Analyzer>::analyze(packet).map(|result| {
            self.life_stamp = life_stamp;
            unsafe {
                // SAFETY: The purpose of this unsafe code is to avoid an allocation each time the
                // builder builds a CacheElement from the data.
                // The first transmute passes from 'b to 'a that lives more than 'b.
                // This will be unsafe if the cache is read from other places without the life_stamp
                // The safety is satisfied with the second transmute returning the original 'b
                // lifetime.
                let analyzer_mem = &mut *self.analyzer_mem.as_mut_ptr();
                *analyzer_mem = std::mem::transmute_copy(&result.analyzer);

                AnalysisResult {
                    analyzer: std::mem::transmute(
                        analyzer_mem as &dyn GenericAnalyzerHandler<'a, I>,
                    ),
                    next_id: result.next_id,
                    bytes: result.bytes,
                }
            }
        })
    }

    unsafe fn get<'c>(&self, life_stamp: usize) -> Option<&dyn GenericAnalyzerHandler<'c, I>> {
        // Only if the life_stamp matches we assume that the resource is created.
        // Function marked as unsafe because life_stamp is a external parameter out of control.
        if self.life_stamp == life_stamp {
            let cache = &*self.analyzer_mem.as_ptr();
            Some(std::mem::transmute(
                cache as &dyn GenericAnalyzerHandler<'a, I>,
            ))
        } else {
            None
        }
    }
}

pub struct AnalyzerCache<I: ClassifierId> {
    builders: Vec<Option<Box<dyn GenericAnalyzerBuilder<I>>>>,
    life_stamp: usize,
}

impl<I: ClassifierId> AnalyzerCache<I> {
    pub fn new(builders: Vec<Option<Box<dyn GenericAnalyzerBuilder<I>>>>) -> Self {
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
    pub fn build_from(
        &mut self,
        id: I,
        packet: &Packet<'a>,
    ) -> Option<AnalysisResult<&dyn GenericAnalyzerHandler<'a, I>, I>> {
        self.cache.builders[id.inner()]
            .as_mut()
            .unwrap_or_else(|| panic!("The ID {:?} must be an associated builder", id))
            .build_from_packet(packet, self.cache.life_stamp)
    }

    pub fn get(&self, id: I) -> Option<&dyn GenericAnalyzerHandler<'a, I>> {
        unsafe {
            // SAFETY: The lifetime of the returned reference is the same as the data lifetime.
            // If the element has not be created, the inner life stamp will not match with this
            // life stamp
            self.cache.builders[id.inner()]
                .as_ref()
                .unwrap_or_else(|| panic!("The ID {:?} must be an associated builder", id))
                .get(self.cache.life_stamp)
        }
    }
}

impl<'a, I: ClassifierId> Drop for CacheFrame<'a, I> {
    fn drop(&mut self) {
        // Increasing the life stamp will invalidate all the references.
        self.cache.life_stamp += 1;
    }
}
