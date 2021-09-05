use crate::ClassifierId;

use gpc_core::base::builder::Builder;

pub struct HttpStartLineBuilder;
impl<'a> Builder<'a, ClassifierId> for HttpStartLineBuilder {
    type Analyzer = analyzer::HttpStartLineAnalyzer<'a>;
}

pub struct HttpHeaderBuilder;
impl<'a> Builder<'a, ClassifierId> for HttpHeaderBuilder {
    type Analyzer = analyzer::HttpHeaderAnalyzer<'a>;
}

mod analyzer {
    use super::flow::HttpFlow;

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

    pub struct HttpStartLineAnalyzer<'a> {
        version: &'a str,
        start_line: StartLine<'a>,
    }

    impl<'a> HttpStartLineAnalyzer<'a> {
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

    impl<'a> Analyzer<'a, ClassifierId> for HttpStartLineAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::HttpStartLine;
        const PREV_ID: ClassifierId = ClassifierId::Tcp;

        type Flow = HttpFlow;

        fn build(&Packet { data, direction }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            let first_line = unsafe {
                //SAFETY: We only check agains first 128 ascii values
                std::str::from_utf8_unchecked(data)
            };

            let mut iter = first_line.splitn(3, ' ');
            let first = iter.next().unwrap();
            let second = iter.next().unwrap();
            let third_and_more = iter.next().unwrap();
            let (third, next_data) = third_and_more.split_once("\r\n").unwrap();

            let (version, start_line) = match direction {
                Direction::Uplink => (
                    third,
                    StartLine::Request {
                        method: first,
                        uri: second,
                    },
                ),
                Direction::Downlink => (
                    first,
                    StartLine::Response {
                        code: second,
                        text: third,
                    },
                ),
            };

            Ok(AnalyzerInfo {
                analyzer: Self {
                    version,
                    start_line,
                },
                next_classifier_id: ClassifierId::HttpHeader,
                bytes_parsed: next_data.as_ptr() as usize - data.as_ptr() as usize,
            })
        }

        fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
            true
        }

        fn create_flow(&self, _direction: Direction) -> HttpFlow {
            HttpFlow {}
        }

        fn update_flow(&self, _flow: &mut HttpFlow, _direction: Direction) {}
    }

    pub struct HttpHeaderAnalyzer<'a> {
        headers: &'a str,
    }

    impl<'a> HttpHeaderAnalyzer<'a> {
        pub fn has_header_key(&self, expected_key: &str) -> bool {
            let mut content = self.headers;
            loop {
                match content.split_once("\r\n") {
                    Some((header_line, next)) => match header_line.split_once(": ") {
                        Some((key, _value)) => {
                            if key == expected_key {
                                break true;
                            }
                            content = next;
                        }
                        None => break false,
                    },
                    None => break false,
                }
            }
        }
    }

    impl<'a> Analyzer<'a, ClassifierId> for HttpHeaderAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::HttpHeader;
        const PREV_ID: ClassifierId = ClassifierId::HttpStartLine;

        type Flow = HttpFlow;

        fn build(&Packet { data, .. }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            let headers = unsafe {
                //SAFETY: We only check agains first 128 ascii values
                std::str::from_utf8_unchecked(data)
            };

            Ok(AnalyzerInfo {
                analyzer: Self { headers },
                next_classifier_id: ClassifierId::None,
                bytes_parsed: 0,
            })
        }

        fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
            true
        }

        fn create_flow(&self, _direction: Direction) -> HttpFlow {
            HttpFlow {}
        }

        fn update_flow(&self, _flow: &mut HttpFlow, _direction: Direction) {}
    }
}

mod flow {
    pub struct HttpFlow {}
}

pub mod expression {
    use super::analyzer::{HttpHeaderAnalyzer, HttpStartLineAnalyzer};
    use super::flow::HttpFlow;

    use crate::ClassifierId;

    use gpc_core::base::expression_value::ExpressionValue;

    #[derive(Debug)]
    pub struct HttpRequest;

    impl ExpressionValue<ClassifierId> for HttpRequest {
        type Builder = super::HttpStartLineBuilder;

        fn description() -> &'static str {
            "Valid if the packet is a request"
        }

        fn check(&self, analyzer: &HttpStartLineAnalyzer, _flow: &HttpFlow) -> bool {
            analyzer.is_request()
        }
    }

    #[derive(Debug)]
    pub struct HttpResponse;

    impl ExpressionValue<ClassifierId> for HttpResponse {
        type Builder = super::HttpStartLineBuilder;

        fn description() -> &'static str {
            "Valid if the packet is a response"
        }

        fn check(&self, analyzer: &HttpStartLineAnalyzer, _flow: &HttpFlow) -> bool {
            !analyzer.is_request()
        }
    }

    pub use super::analyzer::Method as HttpMethod;

    impl ExpressionValue<ClassifierId> for HttpMethod {
        type Builder = super::HttpStartLineBuilder;

        fn description() -> &'static str {
            "Valid if the http request method of the packet"
        }

        fn check(&self, analyzer: &HttpStartLineAnalyzer, _flow: &HttpFlow) -> bool {
            Some(*self) == analyzer.method()
        }
    }

    #[derive(Debug)]
    pub struct HttpCode(pub &'static str);

    impl ExpressionValue<ClassifierId> for HttpCode {
        type Builder = super::HttpStartLineBuilder;

        fn description() -> &'static str {
            "Valid if the http response code of the packet"
        }

        fn check(&self, analyzer: &HttpStartLineAnalyzer, _flow: &HttpFlow) -> bool {
            Some(self.0) == analyzer.code()
        }
    }

    #[derive(Debug)]
    pub struct HttpHeaderName(pub &'static str);

    impl ExpressionValue<ClassifierId> for HttpHeaderName {
        type Builder = super::HttpHeaderBuilder;

        fn description() -> &'static str {
            "Valid if the http packet contains the header name"
        }

        fn check(&self, analyzer: &HttpHeaderAnalyzer, _flow: &HttpFlow) -> bool {
            analyzer.has_header_key(self.0)
        }
    }
}
