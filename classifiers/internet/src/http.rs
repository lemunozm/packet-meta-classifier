use crate::ClassifierId;

use gpc_core::base::builder::Builder;

pub struct HttpBuilder;
impl<'a> Builder<'a, ClassifierId> for HttpBuilder {
    type Analyzer = analyzer::HttpAnalyzer<'a>;
    type Flow = flow::HttpFlow;
}

mod analyzer {
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
    use gpc_core::packet::{Direction, Packet};

    use std::convert::TryFrom;
    use std::io::Write;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Method {
        Get,
        Head,
        Post,
        Put,
        Delete,
        Connect,
        Options,
        Trace,
        Patch,
    }

    impl TryFrom<&str> for Method {
        type Error = ();
        fn try_from(value: &str) -> Result<Self, ()> {
            match value {
                "GET" => Ok(Self::Get),
                "DELETE" => Ok(Self::Delete),
                "CONNECT" => Ok(Self::Connect),
                "OPTIONS" => Ok(Self::Options),
                "TRACE" => Ok(Self::Trace),
                "HEAD" => Ok(Self::Head),
                "POST" => Ok(Self::Post),
                "PUT" => Ok(Self::Put),
                "PATCH" => Ok(Self::Patch),
                _ => Err(()),
            }
        }
    }

    enum StartLine<'a> {
        Request { method: &'a str, uri: &'a str },
        Response { code: &'a str, text: &'a str },
    }

    pub struct HttpAnalyzer<'a> {
        version: &'a str,
        start_line: StartLine<'a>,
    }

    impl<'a> HttpAnalyzer<'a> {
        pub fn method(&self) -> Option<Method> {
            match self.start_line {
                StartLine::Request { method, .. } => Method::try_from(method).ok(),
                StartLine::Response { .. } => None,
            }
        }

        pub fn uri(&self) -> Option<&str> {
            match self.start_line {
                StartLine::Request { uri, .. } => Some(uri),
                StartLine::Response { .. } => None,
            }
        }

        pub fn is_request(&self) -> bool {
            matches!(self.start_line, StartLine::Request { .. })
        }

        pub fn code(&self) -> Option<&str> {
            match self.start_line {
                StartLine::Request { .. } => None,
                StartLine::Response { code, .. } => Some(code),
            }
        }

        pub fn text_code(&self) -> Option<&str> {
            match self.start_line {
                StartLine::Request { .. } => None,
                StartLine::Response { text, .. } => Some(text),
            }
        }

        pub fn version(&self) -> &str {
            self.version
        }
    }

    impl<'a> Analyzer<'a, ClassifierId> for HttpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Http;
        const PREV_ID: ClassifierId = ClassifierId::Tcp;

        fn build(&Packet { data, .. }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            let first_line = unsafe {
                //SAFETY: We only check agains first 128 ascii values
                std::str::from_utf8_unchecked(data)
            };

            let mut iter = first_line.splitn(3, ' ');
            let first = iter.next().unwrap();
            let second = iter.next().unwrap();
            let third_and_more = iter.next().unwrap();
            let (third, _) = third_and_more.split_once("\r\n").unwrap();
            let header_len = first.len() + second.len() + third.len();

            let (version, start_line) = match &data[0..5] == b"HTTP/" {
                true => (
                    first,
                    StartLine::Response {
                        code: second,
                        text: third,
                    },
                ),
                false => (
                    third,
                    StartLine::Request {
                        method: first,
                        uri: second,
                    },
                ),
            };

            Ok(AnalyzerInfo {
                analyzer: HttpAnalyzer {
                    version,
                    start_line,
                },
                next_classifier_id: ClassifierId::None,
                bytes_parsed: header_len,
            })
        }

        fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
            true
        }
    }
}

mod flow {
    use super::analyzer::HttpAnalyzer;

    use gpc_core::base::flow::Flow;
    use gpc_core::packet::Direction;

    pub struct HttpFlow {}

    impl Flow<HttpAnalyzer<'_>> for HttpFlow {
        fn create(_analyzer: &HttpAnalyzer, _direction: Direction) -> Self {
            HttpFlow {}
        }

        fn update(&mut self, _analyzer: &HttpAnalyzer, _direction: Direction) {
            //TODO
        }
    }
}

pub mod expression {
    use super::analyzer::HttpAnalyzer;
    use super::flow::HttpFlow;

    use crate::ClassifierId;

    use gpc_core::base::expression_value::ExpressionValue;

    #[derive(Debug)]
    pub struct HttpRequest;

    impl ExpressionValue<ClassifierId> for HttpRequest {
        type Builder = super::HttpBuilder;

        fn description() -> &'static str {
            "Check if the packet is a request"
        }

        fn check(&self, analyzer: &HttpAnalyzer, _flow: &HttpFlow) -> bool {
            analyzer.is_request()
        }
    }

    #[derive(Debug)]
    pub struct HttpResponse;

    impl ExpressionValue<ClassifierId> for HttpResponse {
        type Builder = super::HttpBuilder;

        fn description() -> &'static str {
            "Check if the packet is a response"
        }

        fn check(&self, analyzer: &HttpAnalyzer, _flow: &HttpFlow) -> bool {
            !analyzer.is_request()
        }
    }

    pub use super::analyzer::Method as HttpMethod;

    impl ExpressionValue<ClassifierId> for HttpMethod {
        type Builder = super::HttpBuilder;

        fn description() -> &'static str {
            "Check if the http request method of the packet"
        }

        fn check(&self, analyzer: &HttpAnalyzer, _flow: &HttpFlow) -> bool {
            Some(*self) == analyzer.method()
        }
    }

    #[derive(Debug)]
    pub struct HttpCode(pub &'static str);

    impl ExpressionValue<ClassifierId> for HttpCode {
        type Builder = super::HttpBuilder;

        fn description() -> &'static str {
            "Check if the http response code of the packet"
        }

        fn check(&self, analyzer: &HttpAnalyzer, _flow: &HttpFlow) -> bool {
            Some(self.0) == analyzer.code()
        }
    }
}
