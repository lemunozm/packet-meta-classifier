use std::fmt::Debug;
use std::hash::Hash;

pub enum ByteAnalysisRule {
    Nothing,
    SkipAnalyzers(usize),
    UnanalyzedPayload,
}

pub trait ClassifierId:
    From<usize> + Into<usize> + Hash + Debug + Copy + Eq + Ord + 'static
{
    const NONE: Self;
    const INITIAL: Self;
    const TOTAL: usize;

    fn inner(self) -> usize {
        self.into()
    }
}

pub struct BaseConfig {
    pub flow_pool_initial_size: usize,
}

pub trait Config: Sized + 'static {
    const BYTE_ANALYSIS_RULE: ByteAnalysisRule;

    type FlowId: Default + Clone + Hash + Eq + Debug;
    type ClassifierId: ClassifierId;

    fn base(&self) -> &BaseConfig;
}
