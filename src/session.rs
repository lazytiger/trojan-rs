use std::io::{Error, ErrorKind, Read, Result, Write};

use bytes::{Buf, BytesMut};

pub struct TcpSession {
    pub recv_buf: BytesMut,
    pub send_buf: BytesMut,
    pub index: usize,
}

impl TcpSession {
    pub fn new(index: usize) -> TcpSession {
        TcpSession {
            recv_buf: BytesMut::new(),
            send_buf: BytesMut::new(),
            index,
        }
    }
    pub fn read_backend<T: Read>(&mut self, reader: &mut T) -> Result<usize> {
        let mut total = 0;
        loop {
            self.recv_buf.reserve(2048);
            let len = self.recv_buf.remaining();
            let cap = self.recv_buf.capacity();
            unsafe {
                self.recv_buf.set_len(cap);
            }
            let buffer = &mut self.recv_buf.as_mut()[len..];
            log::debug!("connection:{} read from backend, len:{}, cap:{}, buffer:{}", self.index, len, cap, buffer.len());
            match reader.read(buffer) {
                Ok(size) => {
                    log::debug!("connection:{} read {} bytes from backend", self.index, size);
                    if size == 0 {
                        if buffer.len() == 0 {
                            log::error!("connection:{} buffer length is zero, something wrong", self.index);
                        }
                        return Err(Error::from(ErrorKind::UnexpectedEof));
                    } else {
                        unsafe {
                            self.recv_buf.set_len(size + len);
                        }
                        total += size;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    unsafe {
                        self.recv_buf.set_len(len);
                    }
                    log::debug!("connection:{} read from backend blocked", self.index);
                    break;
                }
                Err(err) => {
                    unsafe {
                        self.recv_buf.set_len(len);
                    }
                    return Err(err);
                }
            }
        }
        Ok(total)
    }

    pub fn write_backend<T: Write>(&mut self, writer: &mut T) -> Result<usize> {
        let mut len = 0;
        loop {
            if self.send_buf.is_empty() {
                break;
            }
            match writer.write(self.send_buf.bytes()) {
                Ok(size) => {
                    self.send_buf.advance(size);
                    len += size;
                    log::debug!("connection:{} session write {} byte to backend", self.index, size);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("connection:{} session write blocked, remaining:{}", self.index, self.send_buf.len());
                    break;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(len)
    }

    pub fn wants_write(&self) -> bool {
        !self.send_buf.is_empty()
    }

    pub fn read_all(&mut self) -> BytesMut {
        self.recv_buf.split()
    }
}

impl Read for TcpSession {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.recv_buf.copy_to_slice(buf);
        Ok(buf.len())
    }
}

impl Write for TcpSession {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.send_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}