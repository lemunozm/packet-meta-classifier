use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

pub type SharedGenericFlowHandler = Rc<RefCell<dyn GenericFlowHandler>>;

pub trait GenericFlowHandler {
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

pub struct FlowHandler<F>(pub F);

impl<F> FlowHandler<F> {
    pub fn flow(&self) -> &F {
        &self.0
    }
}

impl<F: 'static> GenericFlowHandler for FlowHandler<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}
