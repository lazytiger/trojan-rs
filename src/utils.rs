use crate::types::{
    CopyResult,
    CopyResult::{RxBlock, TxBlock},
    Result, TrojanError,
};
use std::io::{ErrorKind, Read, Write};

pub fn copy_stream(
    from: &mut impl Read,
    to: &mut impl Write,
    buffer: &mut Vec<u8>,
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

pub fn send_all(writer: &mut impl Write, buffer: &mut Vec<u8>) -> Result<bool> {
    log::debug!("start sending {} bytes data", buffer.len());
    if buffer.is_empty() {
        return Ok(true);
    }
    let mut data = buffer.as_slice();
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
        let len = buffer.len() - offset;
        log::debug!("remaining {} bytes, offset:{}", len, offset);
        buffer.copy_within(offset.., 0);
        unsafe {
            buffer.set_len(len);
        }
    }
    ret
}

pub fn read_once(reader: &mut impl Read, buffer: &mut Vec<u8>) -> Result<bool> {
    unsafe {
        buffer.set_len(buffer.capacity());
    }
    let ret = match reader.read(buffer.as_mut_slice()) {
        Ok(0) => Err(TrojanError::RxBreak(None)),
        Ok(n) => {
            log::debug!("read {} bytes", n);
            unsafe {
                buffer.set_len(n);
            }
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(err) => Err(TrojanError::RxBreak(Some(err))),
    };
    if !matches!(ret, Ok(true)) {
        buffer.clear();
    }
    ret
}
