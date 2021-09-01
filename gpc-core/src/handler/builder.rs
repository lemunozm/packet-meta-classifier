use crate::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
use crate::base::builder::Builder;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};
use crate::packet::Packet;

use std::mem::MaybeUninit;

pub trait GenericBuilderHandler<I: ClassifierId> {
    fn build_from_packet<'a>(
        &mut self,
        packet: &Packet<'a>,
        life_stamp: usize,
    ) -> AnalyzerResult<&mut dyn GenericAnalyzerHandler<'a, I>, I>;

    /// This function is unsafe because the caller can choose an incorrect live_stamp that breaks
    /// the life_stamp precondition: the life_stamp parameter should be the same as the used in
    /// the last call to [`build_from_packet()`] ensuring the 'a lifetime endures.
    unsafe fn get<'a>(&self, life_stamp: usize) -> &dyn GenericAnalyzerHandler<'a, I>;
}

impl<I: ClassifierId> dyn GenericBuilderHandler<I> {
    pub fn new<B>(builder: B) -> Box<dyn GenericBuilderHandler<I>>
    where
        B: for<'a> Builder<'a, I> + 'static,
    {
        Box::new(BuilderHandler {
            _builder: builder,
            cached_analyzer: MaybeUninit::uninit(),
            life_stamp: 0,
        })
    }
}

struct BuilderHandler<'a, B, I>
where
    B: Builder<'a, I> + 'static,
    I: ClassifierId,
{
    _builder: B,
    cached_analyzer: MaybeUninit<AnalyzerHandler<B::Analyzer, B::Flow>>,
    life_stamp: usize,
}

impl<'a, B, I> GenericBuilderHandler<I> for BuilderHandler<'a, B, I>
where
    B: for<'b> Builder<'b, I> + 'static,
    I: ClassifierId,
{
    fn build_from_packet<'c>(
        &mut self,
        packet: &Packet<'c>,
        life_stamp: usize,
    ) -> AnalyzerResult<&mut dyn GenericAnalyzerHandler<'c, I>, I> {
        B::Analyzer::build(packet).map(|info| {
            self.life_stamp = life_stamp;
            unsafe {
                // SAFETY: TODO
                let analyzer = &mut *self.cached_analyzer.as_mut_ptr();
                *analyzer = std::mem::transmute_copy(&info.analyzer);

                AnalyzerInfo {
                    analyzer: std::mem::transmute(
                        analyzer as &mut dyn GenericAnalyzerHandler<'a, I>,
                    ),
                    next_classifier_id: info.next_classifier_id,
                    bytes_parsed: info.bytes_parsed,
                }
            }
        })
    }

    unsafe fn get<'c>(&self, life_stamp: usize) -> &dyn GenericAnalyzerHandler<'c, I> {
        if life_stamp != self.life_stamp {
            panic!(
                "Expected life stamp: {}, found: {}",
                self.life_stamp, life_stamp
            );
        }
        let analyzer = &*self.cached_analyzer.as_ptr();
        std::mem::transmute(analyzer as &dyn GenericAnalyzerHandler<'a, I>)
    }
}
