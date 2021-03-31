use crate::packet::Direction;

pub trait Flow<A>: Sized + 'static {
    fn create(analyzer: &A, direction: Direction) -> Self;
    fn update(&mut self, analyzer: &A, direction: Direction);
}

pub struct NoFlow;
impl<A> Flow<A> for NoFlow {
    fn create(_analyzer: &A, _direction: Direction) -> Self {
        NoFlow
    }

    fn update(&mut self, _analyzer: &A, _direction: Direction) {
        panic!("Tried to update a NoFlow");
    }
}
