use std::io::{ErrorKind, Read, Write};

use bytes::{Buf, BytesMut};

use crate::types::{
    CopyResult,
    CopyResult::{RxBlock, TxBlock},
    Result, TrojanError,
};

pub fn copy_stream(
    from: &mut impl Read,
    to: &mut impl Write,
    buffer: &mut BytesMut,
) -> Result<CopyResult> {
    loop {
        if !send_all(to, buffer)? {
            return Ok(TxBlock);
        }
        if !read_once(from, buffer)? {
            return Ok(RxBlock);
        }
    }
}

pub fn send_all(writer: &mut impl Write, buffer: &mut BytesMut) -> Result<bool> {
    if buffer.is_empty() {
        return Ok(true);
    }
    log::debug!("start sending {} bytes data", buffer.len());
    let mut data = buffer.as_ref();
    let mut offset = 0;
    let mut ret = Ok(true);
    while !data.is_empty() {
        ret = match writer.write(data) {
            Ok(0) => Err(TrojanError::TxBreak(None)),
            Ok(n) => {
                log::debug!("sent {} bytes", n);
                offset += n;
                data = &data[n..];
                continue;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(TrojanError::TxBreak(Some(err))),
        };
        break;
    }
    if ret.is_err() {
        buffer.clear();
    } else if offset != 0 {
        buffer.advance(offset);
    }
    ret
}

pub fn read_once(reader: &mut impl Read, buffer: &mut BytesMut) -> Result<bool> {
    buffer.reserve(1500);
    let mut nb = buffer.split_off(buffer.len());
    unsafe {
        nb.set_len(nb.capacity());
    }
    assert!(!nb.as_mut().is_empty());
    let ret = match reader.read(nb.as_mut()) {
        Ok(0) => Err(TrojanError::RxBreak(None)),
        Ok(n) => {
            log::debug!("read {} bytes", n);
            unsafe {
                nb.set_len(n);
            }
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(err) => Err(TrojanError::RxBreak(Some(err))),
    };
    if !matches!(ret, Ok(true)) {
        nb.clear();
    }
    buffer.unsplit(nb);
    ret
}
