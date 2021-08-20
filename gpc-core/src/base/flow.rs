use crate::base::analyzer::Analyzer;
use crate::base::id::ClassifierId;
use crate::packet::Direction;

pub trait Flow<I: ClassifierId>: Sized {
    type Analyzer: for<'a> Analyzer<'a, I>;

    fn create(analyzer: &Self::Analyzer, direction: Direction) -> Self;
    fn update(&mut self, analyzer: &Self::Analyzer, direction: Direction);
}

pub struct NoFlow<A> {
    _analyzer: std::marker::PhantomData<A>,
}

impl<A, I> Flow<I> for NoFlow<A>
where
    A: for<'a> Analyzer<'a, I>,
    I: ClassifierId,
{
    type Analyzer = A;
    fn create(_analyzer: &Self::Analyzer, _direction: Direction) -> Self {
        NoFlow {
            _analyzer: std::marker::PhantomData::default(),
        }
    }

    fn update(&mut self, _analyzer: &Self::Analyzer, _direction: Direction) {
        unreachable!()
    }
}
