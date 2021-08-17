pub struct CapturedPacket {
    //TODO: timestamp
    pub id: usize,
    pub uplink: bool,
    pub data: Vec<u8>,
}

pub trait Capture {
    fn section(&self, first: usize, last: usize) -> CaptureIterator;
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn iter(&self) -> CaptureIterator {
        self.section(1, self.len())
    }
}

pub struct CaptureIterator<'a> {
    packets: &'a [CapturedPacket],
    next: usize,
}

impl<'a> CaptureIterator<'a> {
    pub fn new(packets: &'a [CapturedPacket]) -> Self {
        Self { packets, next: 0 }
    }
}

impl<'a> Iterator for CaptureIterator<'a> {
    type Item = &'a CapturedPacket;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next < self.packets.len() {
            let packet = &self.packets[self.next];
            self.next += 1;
            Some(packet)
        } else {
            None
        }
    }
}
