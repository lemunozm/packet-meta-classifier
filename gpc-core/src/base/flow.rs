use crate::base::id::ClassifierId;
use crate::packet::Direction;

pub trait Flow<A, I: ClassifierId>: Sized {
    fn create(analyzer: &A, direction: Direction) -> Self;
    fn update(&mut self, analyzer: &A, direction: Direction);
}

pub struct NoFlow<A> {
    _analyzer: std::marker::PhantomData<A>,
}

impl<A, I> Flow<A, I> for NoFlow<A>
where
    I: ClassifierId,
{
    fn create(_analyzer: &A, _direction: Direction) -> Self {
        NoFlow {
            _analyzer: std::marker::PhantomData::default(),
        }
    }

    fn update(&mut self, _analyzer: &A, _direction: Direction) {
        unreachable!()
    }
}
