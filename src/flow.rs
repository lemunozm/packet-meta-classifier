use crate::analyzer::{L4Analyzer, FiveTuple, L4};
use crate::classifiers::tcp::flow::{TcpFlow};

use std::collections::{HashMap};

pub trait Flow {
    fn update(&mut self, analyzer: &L4Analyzer);
}

pub struct FlowPool {
    flows: HashMap<FiveTuple, Box<dyn Flow>>
}

impl FlowPool {
    pub fn new() -> FlowPool {
        FlowPool {
            flows: HashMap::new(),
        }
    }

    pub fn get_or_create(&mut self, five_tuple: FiveTuple) -> &mut Box<dyn Flow> {
        match five_tuple.protocol {
            L4::Tcp => self.flows.entry(five_tuple).or_insert(Box::new(TcpFlow::new())),
            _ => unreachable!()
        }
    }

    pub fn update(&mut self) {
        // Update flow timeouts and so on
    }
}
