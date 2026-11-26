use std::io::{self, Cursor, Read};

use super::drain;

struct InterruptedThenData {
    interrupted: bool,
    data: Cursor<&'static [u8]>,
}

impl Read for InterruptedThenData {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.data.read(buffer)
    }
}

#[test]
fn interrupted_read_retries_and_preserves_all_bytes_before_eof() {
    // Interrupted means this read transferred no bytes. It does not mean EOF
    // or that a later read would block, so final capture must retry it.
    let mut pipe = Some(InterruptedThenData {
        interrupted: false,
        data: Cursor::new(b"tail"),
    });
    let mut capture = b"head".to_vec();

    drain(&mut pipe, &mut capture, 8, 5).unwrap();

    assert_eq!(capture, b"headtail");
    assert!(pipe.is_none(), "the retried reader should reach EOF");
}
