use super::analyzer::Analyzer;
use super::id::ClassifierId;

pub trait Flow<I: ClassifierId>: Sized + 'static {
    type Analyzer: Analyzer<I>;
    fn create(analyzer: &Self::Analyzer) -> Self;
    fn update(&mut self, analyzer: &Self::Analyzer);
}

pub struct NoFlow<A> {
    _analyzer: std::marker::PhantomData<A>,
}

impl<A: Analyzer<I>, I: ClassifierId> Flow<I> for NoFlow<A> {
    type Analyzer = A;
    fn create(_analyzer: &Self::Analyzer) -> Self {
        NoFlow {
            _analyzer: std::marker::PhantomData::default(),
        }
    }

    fn update(&mut self, _analyzer: &Self::Analyzer) {
        unreachable!()
    }
}
