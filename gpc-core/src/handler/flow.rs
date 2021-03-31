use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

pub type SharedGenericFlowHandler = Rc<RefCell<dyn GenericFlowHandler>>;

pub trait GenericFlowHandler: 'static {
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl dyn GenericFlowHandler {
    pub fn inner_ref<F: 'static>(&self) -> &F {
        &self.as_any().downcast_ref::<FlowHandler<F>>().unwrap().0
    }

    pub fn inner_mut<F: 'static>(&mut self) -> &mut F {
        &mut self
            .as_mut_any()
            .downcast_mut::<FlowHandler<F>>()
            .unwrap()
            .0
    }

    pub fn new_shared<F: 'static>(flow: F) -> SharedGenericFlowHandler {
        Rc::new(RefCell::new(FlowHandler(flow)))
    }
}

struct FlowHandler<F>(F);

impl<F: 'static> GenericFlowHandler for FlowHandler<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}
