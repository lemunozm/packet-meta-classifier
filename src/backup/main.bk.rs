/*
use packet_classifier::configuration::{Configuration};
use packet_classifier::rules::expression::{Exp};
use packet_classifier::rules::classification::{ClassificationRules};
use packet_classifier::engine::{Engine};
use packet_classifier::classifiers::ipv4::rules::{Ipv4, L4};
use packet_classifier::classifiers::tcp::rules::{Tcp};

use packet_classifier::util::capture::{IpCapture};

fn main() {
    let rules = vec![
        (Exp::value(Ipv4::Origin("127.0.0.1".into())), 200),
        (Exp::value(Ipv4::L4(L4::Udp)), 100),
        (Exp::value(Ipv4::L4(L4::Tcp)), 300),
        (Exp::or(vec![
            Exp::value(Tcp::OriginPort(3000)),
            Exp::value(Tcp::OriginPort(4000)),
        ]), 700),
        (Exp::and(vec![
            Exp::value(Tcp::OriginPort(5000)),
            Exp::value(Tcp::DestinationPort(6000)),
        ]), 800),
    ];

    let config = Configuration::new();
    let classification_rules = ClassificationRules::new(rules);
    let mut engine = Engine::new(config, classification_rules);

    let capture = IpCapture::open("captures/http.cap");
    for (index, packet) in capture[0..].iter().enumerate() {

        let classification_result = engine.process_packet(&packet.data);

        let rule: &dyn std::fmt::Display = match classification_result.rule {
            Some(rule) => rule.tag(),
            None => &"<Not matching rule>"
        };
        println!("[{}]: {}", index, rule);
    }
}
*/

trait AnalyzerDefinition {
    type Analyzer: Analyzer;
    type Flow: Flow;
    type ClassificationValue: ClassificationValue;
    fn uid() -> usize;
}

struct AnalyzerContext<'a> {
    data: &'a [u8],
    analyzer_id: usize,
}

trait L3Analyzer {
    fn analyze_packet(&mut self, data: &[u8]) -> AnalyzerContext<'_>;
}

trait L4Analyzer {
    type LowerAnalyzer: Analyzer;
    fn analyze_packet(&mut self, lower: Self::LowerAnalyzer, data: &[u8]) -> AnalyzerContext<'_>;
}

trait L7Analyzer {
    type L4Analyzer: Analyzer;
    fn analyze_packet(&mut self, lower: Self::LowerAnalyzer, data: &[u8]) -> AnalyzerContext<'_>;
}

trait Flow {
    type Analyzer: Analyzer;
    fn update(&mut self, _analyzer: &Self::Analyzer); //-> AnalyzerResult(Analyzer + )
}

trait ClassificationValue {
    type Analyzer: Analyzer;
    type Flow: Flow;
    fn check(&self, _analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool;
}

//---------------------------
//       No instance
//---------------------------
struct NoAnalyzer;
impl Analyzer for NoAnalyzer {
    type LowerAnalyzer = Self;
    fn analyze_packet(&mut self, _: Self, _: &[u8]) -> AnalyzerContext<'_> { unimplemented!() }
}

struct NoFlow {}
impl Flow for NoFlow {
    type Analyzer = NoAnalyzer;
    fn update(&mut self, _: &NoAnalyzer) {}
}

//---------------------------
//           Ipv4
//---------------------------
struct Ipv4AnalyzerDefinition;
impl AnalyzerDefinition for Ipv4AnalyzerDefinition {
    type Analyzer = Ipv4Analyzer;
    type Flow = NoFlow;
    type ClassificationValue = Ipv4;
    fn uid() -> usize {
        todo!()
    }
}

struct Ipv4Analyzer;
impl Analyzer for Ipv4Analyzer {
    type LowerAnalyzer = NoAnalyzer;
    fn analyze_packet(&mut self, _: NoAnalyzer, _data: &[u8]) -> AnalyzerContext<'_> {
        todo!()
    }
}

pub enum L4 {
    Udp,
    Tcp,
}

enum Ipv4 {
    Src(String),
    Dst(String),
    L4(L4),
}

impl ClassificationValue for Ipv4 {
    type Analyzer = Ipv4Analyzer;
    type Flow = NoFlow;
    fn check(&self, _analyzer: &Ipv4Analyzer, _flow: &NoFlow) -> bool {
        todo!()
    }
}

//---------------------------
//            Tcp
//---------------------------
struct TcpAnalyzerDefinition;
impl AnalyzerDefinition for TcpAnalyzerDefinition {
    type Analyzer = TcpAnalyzer;
    type Flow = TcpFlow;
    type ClassificationValue = Tcp;
    fn uid() -> usize {
        todo!()
    }
}

struct TcpAnalyzer;
impl Analyzer for TcpAnalyzer {
    type LowerAnalyzer = Ipv4Analyzer;
    fn analyze_packet(&mut self, _l3: Ipv4Analyzer, _data: &[u8]) -> AnalyzerContext<'_> {
        todo!()
    }
}

struct TcpFlow;
impl Flow for TcpFlow {
    type Analyzer = TcpAnalyzer;
    fn update(&mut self, _analyzer: &TcpAnalyzer) {
        todo!()
    }
}

enum Tcp {
    SrcPort(u16),
    DstPort(u16),
}

impl ClassificationValue for Tcp {
    type Analyzer = TcpAnalyzer;
    type Flow = TcpFlow;
    fn check(&self, _analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
        todo!()
    }
}

//---------------------------
//           Core
//---------------------------
use std::collections::{HashMap};

trait Checkable {
    fn check(&self) -> bool;
}

trait Analyzable {
    fn analyze_packet(&mut self, data: &[u8]) -> AnalyzerContext<'_>;
}

struct AnalyzerEntry<A: Analyzer, F: Flow> {
    analyzer: A,
    //flow_pool: HashMap<usize,F>,
    current_flow: F,
    classification_value: Box<dyn ClassificationValue<Analyzer = A, Flow = F>>
}

impl<A: Analyzer, F: Flow> Checkable for AnalyzerEntry<A, F> {
    fn check(&self) -> bool {
        self.classification_value.check(&self.analyzer, &self.current_flow)
    }
}

impl<A: Analyzer, F: Flow> Analyzable for AnalyzerEntry<A, F> {
    fn analyze_packet(&mut self, data: &[u8]) -> AnalyzerContext<'_> {
        self.analyzer.analyze_packet(data)
        //self.flow.
    }
}

struct Engine {
}

impl Engine {
    fn classify(&mut self, data: &[u8]) {
        let pipeline = AnalyzerPipeline;
        pipeline.l4 = pipeline.l3.analyze_packet(data);
        pipeline.l7 = pipeline.l4.analyze_packet(data);
        pipeline.l7.analyze_packet(data);


        let mut analyzer = Ipv4Analyzer;
        let mut context = analyzer.analyze_packet(NoAnalyzer, data);
        AnalyzerType::
        analyzer = store.get(context.analyzer_id).analyze_packet(analyzer)
        analyzer.analyze_packet();

        let mut context = AnalyzerContext{data, analyzer_id: 1};
        while context.analyzer_id != 0 {
            let analyzer = &mut self.analyzers[context.analyzer_id];
            context = analyzer.analyze_packet(data);
        }
    }
}

fn main() {
}
