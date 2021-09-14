use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

pub type SharedFlowController = Rc<RefCell<dyn FlowController>>;

pub trait FlowController: 'static {
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
    fn associate_index(&mut self, index: usize);
    fn associated_index(&self) -> Option<usize>;
    fn delete_associated_index(&mut self);
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
        Rc::new(RefCell::new(ControllerImpl(flow, None)))
    }
}

struct ControllerImpl<F>(F, Option<usize>);

impl<F: 'static> FlowController for ControllerImpl<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }

    fn associate_index(&mut self, index: usize) {
        self.1 = Some(index);
    }

    fn associated_index(&self) -> Option<usize> {
        self.1
    }

    fn delete_associated_index(&mut self) {
        self.1 = None;
    }
}
