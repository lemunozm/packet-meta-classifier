use super::config::Config;

use super::ClassificationResult;
use super::ClassificationRules;
use super::ClassificationState;
use super::Flow;
use super::FlowDef;
use super::FlowKind;
use super::HttpFlow;
use super::PacketInfo;
use super::UdpFlow;

use crate::classifiers::tcp::flow::TcpFlow;
use crate::classifiers::AnalyzerKind;

use std::collections::HashMap;

pub struct Engine<T> {
    config: Config,
    rules: ClassificationRules<T>,
    packet: PacketInfo,
    flow_pool: HashMap<FlowDef, Box<dyn Flow>>,
}

impl<T> Engine<T> {
    pub fn new(config: Config, rules: ClassificationRules<T>) -> Engine<T> {
        Engine {
            config,
            rules,
            packet: PacketInfo::default(),
            flow_pool: HashMap::new(),
        }
    }

    fn process_packet(&mut self, mut data: &[u8]) -> ClassificationResult<T> {
        let mut analyzers: u64 = 0;
        let mut analyzer = AnalyzerKind::START;

        loop {
            let (next_analyzer, next_data) = self.packet.process_for(analyzer, data);
            let flow = match self.packet.flow_def(analyzer) {
                Some(flow_def) => {
                    let flow = self.flow_pool.entry(flow_def.clone()).or_insert_with(|| {
                        match flow_def.kind {
                            FlowKind::Udp => Box::new(UdpFlow::default()),
                            FlowKind::Tcp => Box::new(TcpFlow::default()),
                            FlowKind::Http => Box::new(HttpFlow::default()),
                        }
                    });

                    flow.update(&self.packet);
                    Some(&*flow)
                }
                None => None,
            };

            match self.rules.try_classify(analyzers, &self.packet, flow) {
                ClassificationState::None => return ClassificationResult { rule: None },
                ClassificationState::Incompleted => (),
                ClassificationState::Completed(rule) => {
                    return ClassificationResult { rule: Some(rule) }
                }
            };

            analyzers |= analyzer as u64;
            data = next_data;
            match next_analyzer {
                Some(next_analyzer) => analyzer = next_analyzer,
                None => break,
            }
        }

        ClassificationResult { rule: None }
    }
}
