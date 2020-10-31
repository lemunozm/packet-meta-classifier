#[derive(Debug)]
pub enum L2 {
    Ethernet,
}

#[derive(Debug)]
pub enum L3 {
    Ip,
}

#[derive(Debug)]
pub enum L4 {
    Tcp,
    Udp,
    Dns,
}

#[derive(Debug)]
pub enum L5 {
    Http,
}

#[derive(Debug)]
pub enum Tcp {
    SynFlood,
    Teardown,
}

#[derive(Debug)]
pub enum Value {
    L2(L2),
    L3(L3),
    L4(L4),
    L5(L5),
    Tcp(Tcp),
}

#[derive(Debug)]
pub enum Op {
    And(Vec<Rule>),
    Or(Vec<Rule>),
}

#[derive(Debug)]
pub enum Rule {
    Value(Value),
    Op(Op),
}
