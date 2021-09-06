use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

pub type SharedFlowController = Rc<RefCell<dyn FlowController>>;

pub trait FlowController: 'static {
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl dyn FlowController {
    pub fn inner_ref<F: 'static>(&self) -> &F {
        &self.as_any().downcast_ref::<ControllerImpl<F>>().unwrap().0
    }

    pub fn inner_mut<F: 'static>(&mut self) -> &mut F {
        &mut self
            .as_mut_any()
            .downcast_mut::<ControllerImpl<F>>()
            .unwrap()
            .0
    }

    pub fn new_shared<F: 'static>(flow: F) -> SharedFlowController {
        Rc::new(RefCell::new(ControllerImpl(flow)))
    }
}

struct ControllerImpl<F>(F);

impl<F: 'static> FlowController for ControllerImpl<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}
