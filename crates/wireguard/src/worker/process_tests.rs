//! Independent stream contracts: fragments and I/O outcomes are scripted, not
//! encoded with the production codec or obtained from an OS timing race.
use super::{IO_BYTES, IO_CALLS, MAX_FRAME_BYTES, Pipe, WorkerError};
use std::{
    collections::VecDeque,
    io::{self, ErrorKind, Read, Write},
};
use zeroize::Zeroizing;

enum ReadStep {
    Bytes(Vec<u8>),
    Interrupted,
    WouldBlock,
    Eof,
    Failed,
}
#[derive(Default)]
struct Reader {
    steps: VecDeque<ReadStep>,
    calls: usize,
    bytes: usize,
}
impl Reader {
    fn append(&mut self, steps: impl IntoIterator<Item = ReadStep>) {
        self.steps.extend(steps);
    }
}
impl Read for Reader {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        match self.steps.pop_front().unwrap_or(ReadStep::WouldBlock) {
            ReadStep::Bytes(bytes) => {
                assert!(!target.is_empty());
                let count = bytes.len().min(target.len());
                target[..count].copy_from_slice(&bytes[..count]);
                self.bytes += count;
                if count < bytes.len() {
                    self.steps
                        .push_front(ReadStep::Bytes(bytes[count..].to_vec()));
                }
                Ok(count)
            }
            ReadStep::Interrupted => Err(ErrorKind::Interrupted.into()),
            ReadStep::WouldBlock => Err(ErrorKind::WouldBlock.into()),
            ReadStep::Eof => Ok(0),
            ReadStep::Failed => Err(ErrorKind::BrokenPipe.into()),
        }
    }
}

enum WriteStep {
    Limit(usize),
    Interrupted,
    WouldBlock,
    Failed,
}
#[derive(Default)]
struct Writer {
    steps: VecDeque<WriteStep>,
    captured: Vec<u8>,
    calls: usize,
}
impl Write for Writer {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        match self
            .steps
            .pop_front()
            .unwrap_or(WriteStep::Limit(usize::MAX))
        {
            WriteStep::Limit(maximum) => {
                let count = source.len().min(maximum);
                self.captured.extend_from_slice(&source[..count]);
                Ok(count)
            }
            WriteStep::Interrupted => Err(ErrorKind::Interrupted.into()),
            WriteStep::WouldBlock => Err(ErrorKind::WouldBlock.into()),
            WriteStep::Failed => Err(ErrorKind::BrokenPipe.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn frame(body: &[u8]) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn full_reply_at_byte_budget_is_immediate_work_before_waiting_for_fd() {
    let body = vec![0x71; IO_BYTES - 4];
    let wire = frame(&body);
    let mut pipe = Pipe::new();
    let mut writer = Writer::default();
    let mut reader = Reader::default();
    reader.append([ReadStep::Bytes(wire)]);
    assert!(!pipe.has_complete_buffered_frame());

    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert_eq!(reader.bytes, IO_BYTES);
    assert!(reader.steps.is_empty(), "the OS pipe has no unread bytes");
    assert!(pipe.has_complete_buffered_frame());

    // The next nonblocking probe must still validate the no-trailing-byte rule.
    assert_eq!(
        pipe.poll(&mut writer, &mut reader)
            .unwrap()
            .unwrap()
            .as_slice(),
        body
    );
    assert!(!pipe.has_complete_buffered_frame());
}

#[test]
fn full_reply_at_call_budget_is_immediate_work_before_waiting_for_fd() {
    let body = [1, 4, 0x71];
    let wire = frame(&body);
    let mut pipe = Pipe::new();
    let mut writer = Writer::default();
    let mut reader = Reader::default();
    reader.append((0..IO_CALLS - 2).map(|_| ReadStep::Interrupted));
    reader.append([
        ReadStep::Bytes(wire[..4].to_vec()),
        ReadStep::Bytes(body.to_vec()),
    ]);

    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert_eq!(reader.calls, IO_CALLS);
    assert!(reader.steps.is_empty(), "the OS pipe has no unread bytes");
    assert!(pipe.has_complete_buffered_frame());

    // Readiness must not bypass protocol validation if a trailing byte arrives.
    reader.append([ReadStep::Bytes(vec![0x72])]);
    assert!(matches!(
        pipe.poll(&mut writer, &mut reader),
        Err(WorkerError::Protocol)
    ));
}

#[test]
fn partial_frames_do_not_report_immediate_work_and_spin_the_waiter() {
    let mut pipe = Pipe::new();
    let mut writer = Writer::default();
    let mut reader = Reader::default();
    assert!(!pipe.has_complete_buffered_frame());
    reader.append([ReadStep::Bytes(vec![3, 0]), ReadStep::WouldBlock]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert!(!pipe.has_complete_buffered_frame());

    reader.append([
        ReadStep::Bytes(vec![0, 0]),
        ReadStep::Bytes(vec![1]),
        ReadStep::WouldBlock,
    ]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert_eq!(pipe.header_read, 4);
    assert_eq!(pipe.body_read, 1);
    assert!(!pipe.has_complete_buffered_frame());
}

#[test]
fn partial_prefix_and_body_survive_interrupted_and_would_block_reads() {
    let mut pipe = Pipe::new();
    let mut writer = Writer::default();
    let mut reader = Reader::default();
    let body = [1, 4, 9, 8, 7];
    let wire = frame(&body);
    reader.append([ReadStep::Bytes(wire[..1].to_vec()), ReadStep::WouldBlock]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert_eq!(pipe.header_read, 1);
    assert!(pipe.body.is_empty());
    reader.append([
        ReadStep::Interrupted,
        ReadStep::Bytes(wire[1..4].to_vec()),
        ReadStep::Bytes(body[..1].to_vec()),
        ReadStep::WouldBlock,
    ]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert_eq!(pipe.header_read, 4);
    assert_eq!(pipe.body_read, 1);
    reader.append([
        ReadStep::Bytes(body[1..].to_vec()),
        ReadStep::Interrupted,
        ReadStep::WouldBlock,
    ]);
    assert_eq!(
        pipe.poll(&mut writer, &mut reader)
            .unwrap()
            .unwrap()
            .as_slice(),
        body
    );
    assert_eq!(reader.bytes, wire.len());
    assert_eq!(pipe.header_read, 0);
    assert_eq!(pipe.body_read, 0);
    assert!(pipe.body.is_empty());
}

#[test]
fn short_writes_and_retryable_errors_never_duplicate_or_drop_bytes() {
    let mut pipe = Pipe::new();
    let mut writer = Writer::default();
    let mut reader = Reader::default();
    let bytes = frame(&[1, 3, 11, 12, 13]);
    pipe.queue(Zeroizing::new(bytes.clone())).unwrap();
    writer.steps.extend([
        WriteStep::Limit(2),
        WriteStep::Interrupted,
        WriteStep::WouldBlock,
    ]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert!(pipe.pending_write());
    assert_eq!(writer.captured, bytes[..2]);
    writer
        .steps
        .extend([WriteStep::Limit(1), WriteStep::WouldBlock]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert!(pipe.pending_write());
    assert_eq!(writer.captured, bytes[..3]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert!(!pipe.pending_write());
    assert_eq!(writer.captured, bytes);
    assert_eq!(pipe.written, 0);
    assert!(pipe.tx.is_empty());
}

#[test]
fn each_direction_has_its_own_sixteen_kibibyte_poll_budget() {
    let body = vec![0x5a; MAX_FRAME_BYTES];
    let bytes = frame(&body);
    let mut pipe = Pipe::new();
    pipe.queue(Zeroizing::new(bytes.clone())).unwrap();
    let mut writer = Writer::default();
    let mut reader = Reader::default();
    reader.append([ReadStep::Bytes(bytes.clone())]);
    let received = loop {
        let (written_before, read_before) = (writer.captured.len(), reader.bytes);
        let result = pipe.poll(&mut writer, &mut reader).unwrap();
        assert!(writer.captured.len() - written_before <= IO_BYTES);
        assert!(reader.bytes - read_before <= IO_BYTES);
        if let Some(result) = result {
            break result;
        }
    };
    assert_eq!(received.as_slice(), body);
    assert_eq!(writer.captured, bytes);
    assert!(!pipe.pending_write());
}

#[test]
fn repeated_interruptions_cannot_exceed_thirty_two_calls_per_direction() {
    let mut pipe = Pipe::new();
    let bytes = frame(&[1, 1]);
    pipe.queue(Zeroizing::new(bytes.clone())).unwrap();
    let mut writer = Writer::default();
    writer
        .steps
        .extend((0..IO_CALLS).map(|_| WriteStep::Interrupted));
    let mut reader = Reader::default();
    reader.append((0..IO_CALLS).map(|_| ReadStep::Interrupted));
    reader.append([ReadStep::Bytes(bytes.clone())]);
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert_eq!(writer.calls, IO_CALLS);
    assert_eq!(reader.calls, IO_CALLS);
    assert!(writer.captured.is_empty());
    assert_eq!(reader.bytes, 0);
    assert_eq!(
        pipe.poll(&mut writer, &mut reader)
            .unwrap()
            .unwrap()
            .as_slice(),
        [1, 1]
    );
    assert_eq!(writer.captured, bytes);
}

#[test]
fn completed_frame_survives_interruptions_while_checking_for_trailing_bytes() {
    let mut pipe = Pipe::new();
    let mut writer = Writer::default();
    let mut reader = Reader::default();
    reader.append([ReadStep::Bytes(frame(&[1, 1]))]);
    reader.append((0..IO_CALLS - 2).map(|_| ReadStep::Interrupted));
    assert!(pipe.poll(&mut writer, &mut reader).unwrap().is_none());
    assert_eq!(reader.calls, IO_CALLS);
    assert_eq!(
        pipe.poll(&mut writer, &mut reader)
            .unwrap()
            .unwrap()
            .as_slice(),
        [1, 1]
    );
}

#[test]
fn invalid_lengths_reject_before_body_allocation_or_read() {
    for length in [0, 1, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
        let mut pipe = Pipe::new();
        let mut writer = Writer::default();
        let mut reader = Reader::default();
        reader.append([
            ReadStep::Bytes(length.to_le_bytes().to_vec()),
            ReadStep::Bytes(vec![0; 4]),
        ]);
        assert_eq!(
            pipe.poll(&mut writer, &mut reader),
            Err(WorkerError::Protocol)
        );
        assert_eq!(reader.bytes, 4);
        assert_eq!(reader.calls, 1);
        assert_eq!(pipe.body.capacity(), 0);
    }
}

#[test]
fn eof_at_partial_prefix_or_body_is_not_a_complete_frame() {
    let wire = frame(&[1, 4, 9, 8, 7]);
    for length in [0, 2, 4, wire.len() - 1] {
        let mut pipe = Pipe::new();
        let mut writer = Writer::default();
        let mut reader = Reader::default();
        if length != 0 {
            reader.append([ReadStep::Bytes(wire[..length].to_vec())]);
        }
        reader.append([ReadStep::Eof]);
        assert_eq!(pipe.poll(&mut writer, &mut reader), Err(WorkerError::Io));
    }
}

#[test]
fn trailing_byte_duplicate_frame_and_eof_suppress_the_complete_reply() {
    for trailing in [
        ReadStep::Bytes(vec![0]),
        ReadStep::Bytes(frame(&[1, 1])),
        ReadStep::Eof,
    ] {
        let mut pipe = Pipe::new();
        let mut writer = Writer::default();
        let mut reader = Reader::default();
        reader.append([ReadStep::Bytes(frame(&[1, 1])), trailing]);
        assert_eq!(
            pipe.poll(&mut writer, &mut reader),
            Err(WorkerError::Protocol)
        );
    }
}

#[test]
fn blocked_writer_does_not_prevent_bounded_reads() {
    let mut pipe = Pipe::new();
    let outgoing = frame(&[1, 3]);
    pipe.queue(Zeroizing::new(outgoing)).unwrap();
    let mut writer = Writer::default();
    writer.steps.push_back(WriteStep::WouldBlock);
    let mut reader = Reader::default();
    reader.append([ReadStep::Bytes(frame(&[1, 1]))]);
    assert_eq!(
        pipe.poll(&mut writer, &mut reader)
            .unwrap()
            .unwrap()
            .as_slice(),
        [1, 1]
    );
    assert!(pipe.pending_write());
    assert!(writer.captured.is_empty());
}

#[test]
fn queue_rejection_does_not_replace_pending_bytes() {
    let mut pipe = Pipe::new();
    let first = frame(&[1, 3, 7]);
    pipe.queue(Zeroizing::new(first.clone())).unwrap();
    assert_eq!(
        pipe.queue(Zeroizing::new(frame(&[1, 3, 8]))),
        Err(WorkerError::Protocol)
    );
    assert_eq!(pipe.tx.as_slice(), first);
    let mut pipe = Pipe::new();
    assert_eq!(
        pipe.queue(Zeroizing::new(vec![0; MAX_FRAME_BYTES + 5])),
        Err(WorkerError::Protocol)
    );
    assert!(!pipe.pending_write());
}

#[test]
fn permanent_io_errors_and_zero_writes_fail_closed() {
    for step in [WriteStep::Failed, WriteStep::Limit(0)] {
        let mut pipe = Pipe::new();
        pipe.queue(Zeroizing::new(frame(&[1, 3]))).unwrap();
        let mut writer = Writer::default();
        writer.steps.push_back(step);
        assert_eq!(
            pipe.poll(&mut writer, &mut Reader::default()),
            Err(WorkerError::Io)
        );
    }
    let mut pipe = Pipe::new();
    let mut reader = Reader::default();
    reader.append([ReadStep::Failed]);
    assert_eq!(
        pipe.poll(&mut Writer::default(), &mut reader),
        Err(WorkerError::Io)
    );
}
