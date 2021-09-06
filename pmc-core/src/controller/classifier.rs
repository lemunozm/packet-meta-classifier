use crate::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
use crate::base::classifier::Classifier;
use crate::base::id::ClassifierId;
use crate::controller::analyzer::{AnalyzerController, AnalyzerControllerImpl};
use crate::packet::Packet;

pub trait ClassifierController<I: ClassifierId> {
    /// SAFETY: Satisfied by the caller. The caller must ensure to call clean()
    /// before 'a lifetime ends.
    unsafe fn build_analyzer<'a>(
        &mut self,
        packet: &Packet<'a>,
    ) -> AnalyzerResult<&dyn AnalyzerController<'a, I>, I>;

    /// SAFETY: Satisfied by the user. The caller must ensure the lifetime used during
    /// `build_analyzer()` is still valid.
    unsafe fn get<'a>(&self) -> &dyn AnalyzerController<'a, I>;

    /// SAFETY: Satisfied by the caller. To avoid a possible unbehavior while dropping, this
    /// phase must be doing during the 'packet lifetime used in `build_analyzer()`
    unsafe fn clean(&mut self);
}

impl<I: ClassifierId> dyn ClassifierController<I> {
    pub fn new<C>(classifier: C) -> Box<dyn ClassifierController<I>>
    where
        C: for<'a> Classifier<'a, I> + 'static,
    {
        Box::new(ControllerImpl {
            _classifier: classifier,
            cached_analyzer: None,
        })
    }
}

struct ControllerImpl<'a, C, I>
where
    C: Classifier<'a, I> + 'static,
    I: ClassifierId,
{
    _classifier: C,
    cached_analyzer: Option<AnalyzerControllerImpl<C::Analyzer>>,
}

impl<'a, C, I> ClassifierController<I> for ControllerImpl<'a, C, I>
where
    C: for<'b> Classifier<'b, I> + 'static,
    I: ClassifierId,
{
    unsafe fn build_analyzer<'c>(
        &mut self,
        packet: &Packet<'c>,
    ) -> AnalyzerResult<&dyn AnalyzerController<'c, I>, I> {
        if self.cached_analyzer.is_some() {
            panic!("Analyzer already built. A call to clean() is necessary to rebuild an analyzer");
        }

        C::Analyzer::build(packet).map(|info| {
            let controller = AnalyzerControllerImpl::<C::Analyzer>::new(info.analyzer);
            let controller = unsafe { std::mem::transmute_copy(&controller) };

            let generic_analyzer =
                self.cached_analyzer.insert(controller) as &dyn AnalyzerController<'a, I>;

            let generic_analyzer = unsafe {
                // SAFETY: Ok. Restored the 'c lifetime while 'c is still valid.
                std::mem::transmute::<
                    &dyn AnalyzerController<'a, I>,
                    &dyn AnalyzerController<'c, I>,
                >(generic_analyzer)
            };

            AnalyzerInfo {
                analyzer: generic_analyzer,
                next_classifier_id: info.next_classifier_id,
                bytes_parsed: info.bytes_parsed,
            }
        })
    }

    unsafe fn get<'c>(&self) -> &dyn AnalyzerController<'c, I> {
        let generic_analyzer =
            self.cached_analyzer
                .as_ref()
                .expect("Analyzer must be built") as &dyn AnalyzerController<'a, I>;

        std::mem::transmute::<&dyn AnalyzerController<'a, I>, &dyn AnalyzerController<'c, I>>(
            generic_analyzer,
        )
    }

    unsafe fn clean(&mut self) {
        self.cached_analyzer.take().expect("Analyzer must be built");
    }
}
