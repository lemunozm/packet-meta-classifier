use crate::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
use crate::base::builder::Builder;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};
use crate::packet::Packet;

pub trait GenericBuilderHandler<I: ClassifierId> {
    /// SAFETY: Satisfied by the caller. The caller must ensure to call clean()
    /// before 'a lifetime ends.
    unsafe fn build_from_packet<'a>(
        &mut self,
        packet: &Packet<'a>,
    ) -> AnalyzerResult<&dyn GenericAnalyzerHandler<'a, I>, I>;

    /// SAFETY: Satisfied by the user. The caller must ensure the lifetime used during
    /// `build_from_packet()` is still valid.
    unsafe fn get<'a>(&self) -> &dyn GenericAnalyzerHandler<'a, I>;

    /// SAFETY: Satisfied by the caller. To avoid a possible unbehavior while dropping, this
    /// phase must be doing during the 'packet lifetime used in `build_from_packet()`
    unsafe fn clean(&mut self);
}

impl<I: ClassifierId> dyn GenericBuilderHandler<I> {
    pub fn new<B>(builder: B) -> Box<dyn GenericBuilderHandler<I>>
    where
        B: for<'a> Builder<'a, I> + 'static,
    {
        Box::new(BuilderHandler {
            _builder: builder,
            cached_analyzer: None,
        })
    }
}

struct BuilderHandler<'a, B, I>
where
    B: Builder<'a, I> + 'static,
    I: ClassifierId,
{
    _builder: B,
    cached_analyzer: Option<AnalyzerHandler<B::Analyzer, B::Flow>>,
}

impl<'a, B, I> GenericBuilderHandler<I> for BuilderHandler<'a, B, I>
where
    B: for<'b> Builder<'b, I> + 'static,
    I: ClassifierId,
{
    unsafe fn build_from_packet<'c>(
        &mut self,
        packet: &Packet<'c>,
    ) -> AnalyzerResult<&dyn GenericAnalyzerHandler<'c, I>, I> {
        if self.cached_analyzer.is_some() {
            panic!("Analyzer already built. A call to clean() is necessary to rebuild an analyzer");
        }

        B::Analyzer::build(packet).map(|info| {
            let handler = AnalyzerHandler::<B::Analyzer, B::Flow>::new(info.analyzer);
            let handler = unsafe { std::mem::transmute_copy(&handler) };

            let generic_analyzer =
                self.cached_analyzer.insert(handler) as &dyn GenericAnalyzerHandler<'a, I>;

            let generic_analyzer = unsafe {
                // SAFETY: Ok. Restored the 'c lifetime while 'c is still valid.
                std::mem::transmute::<
                    &dyn GenericAnalyzerHandler<'a, I>,
                    &dyn GenericAnalyzerHandler<'c, I>,
                >(generic_analyzer)
            };

            AnalyzerInfo {
                analyzer: generic_analyzer,
                next_classifier_id: info.next_classifier_id,
                bytes_parsed: info.bytes_parsed,
            }
        })
    }

    unsafe fn get<'c>(&self) -> &dyn GenericAnalyzerHandler<'c, I> {
        let generic_analyzer =
            self.cached_analyzer
                .as_ref()
                .expect("Analyzer must be built") as &dyn GenericAnalyzerHandler<'a, I>;

        std::mem::transmute::<&dyn GenericAnalyzerHandler<'a, I>, &dyn GenericAnalyzerHandler<'c, I>>(
            generic_analyzer,
        )
    }

    unsafe fn clean(&mut self) {
        let mut generic_analyzer = self.cached_analyzer.take().expect("Analyzer must be built");

        std::ptr::drop_in_place(
            &mut generic_analyzer as *mut AnalyzerHandler<B::Analyzer, B::Flow>,
        );
    }
}
