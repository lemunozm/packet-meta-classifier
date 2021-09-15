use crate::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult, UseFlow};
use crate::base::classifier::Classifier;
use crate::base::config::Config;
use crate::controller::analyzer::{AnalyzerController, AnalyzerControllerImpl};
use crate::controller::flow::{FlowController, SharedFlowController};
use crate::packet::Packet;

pub trait ClassifierController<C: Config> {
    fn update_flow_id(&self, flow_id: &mut C::FlowId, packet: &Packet) -> UseFlow;

    fn build_flow(&self) -> SharedFlowController;

    /// SAFETY: Satisfied by the caller. The caller must ensure to call clean()
    /// before 'a lifetime ends.
    unsafe fn build_analyzer<'a>(
        &mut self,
        config: &C,
        packet: &Packet<'a>,
        flow: Option<&dyn FlowController>,
    ) -> AnalyzerResult<&dyn AnalyzerController<'a, C>, C::ClassifierId>;

    /// SAFETY: Satisfied by the user. The caller must ensure the lifetime used during
    /// `build_analyzer()` is still valid.
    unsafe fn get<'a>(&self) -> &dyn AnalyzerController<'a, C>;

    /// SAFETY: Satisfied by the caller. To avoid a possible unbehavior while dropping, this
    /// phase must be doing during the 'packet lifetime used in `build_analyzer()`
    unsafe fn clean(&mut self);
}

impl<C: Config> dyn ClassifierController<C> {
    pub fn new<B>(classifier: B) -> Box<dyn ClassifierController<C>>
    where
        B: for<'a> Classifier<'a, C> + 'static,
    {
        Box::new(ControllerImpl {
            _classifier: classifier,
            cached_analyzer: None,
        })
    }
}

struct ControllerImpl<'a, B, C>
where
    B: Classifier<'a, C> + 'static,
    C: Config,
{
    _classifier: B,
    cached_analyzer: Option<AnalyzerControllerImpl<B::Analyzer>>,
}

impl<'a, B, C> ClassifierController<C> for ControllerImpl<'a, B, C>
where
    B: for<'b> Classifier<'b, C> + 'static,
    C: Config,
{
    fn update_flow_id(&self, flow_id: &mut C::FlowId, packet: &Packet) -> UseFlow {
        B::Analyzer::update_flow_id(flow_id, packet)
    }

    fn build_flow(&self) -> SharedFlowController {
        let flow = <B::Analyzer as Analyzer<C>>::Flow::default();
        <dyn FlowController>::new_shared(flow)
    }

    unsafe fn build_analyzer<'c>(
        &mut self,
        config: &C,
        packet: &Packet<'c>,
        flow: Option<&dyn FlowController>,
    ) -> AnalyzerResult<&dyn AnalyzerController<'c, C>, C::ClassifierId> {
        if self.cached_analyzer.is_some() {
            panic!("Analyzer already built. A call to clean() is necessary to rebuild an analyzer");
        }

        let analyzer = match flow {
            Some(flow) => {
                let inner_flow = flow.inner_ref::<<B::Analyzer as Analyzer<C>>::Flow>();
                B::Analyzer::build(config, packet, inner_flow)
            }
            None => {
                let no_flow = <B::Analyzer as Analyzer<C>>::Flow::default();
                B::Analyzer::build(config, packet, &no_flow)
            }
        };

        analyzer.map(|info| {
            let controller = AnalyzerControllerImpl::<B::Analyzer>::new(info.analyzer);
            let controller = unsafe { std::mem::transmute_copy(&controller) };

            let generic_analyzer =
                self.cached_analyzer.insert(controller) as &dyn AnalyzerController<'a, C>;

            let generic_analyzer = unsafe {
                // SAFETY: Ok. Restored the 'c lifetime while 'c is still valid.
                std::mem::transmute::<
                    &dyn AnalyzerController<'a, C>,
                    &dyn AnalyzerController<'c, C>,
                >(generic_analyzer)
            };

            AnalyzerInfo {
                analyzer: generic_analyzer,
                next_classifier_id: info.next_classifier_id,
                bytes_parsed: info.bytes_parsed,
            }
        })
    }

    unsafe fn get<'c>(&self) -> &dyn AnalyzerController<'c, C> {
        let generic_analyzer =
            self.cached_analyzer
                .as_ref()
                .expect("Analyzer must be built") as &dyn AnalyzerController<'a, C>;

        std::mem::transmute::<&dyn AnalyzerController<'a, C>, &dyn AnalyzerController<'c, C>>(
            generic_analyzer,
        )
    }

    unsafe fn clean(&mut self) {
        self.cached_analyzer.take().expect("Analyzer must be built");
    }
}
