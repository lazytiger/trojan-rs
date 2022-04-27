use bytes::{Buf, BytesMut};

#[test]
fn bytes_memory() {
    let mut buffer = BytesMut::new();
    buffer.extend_from_slice("hello, world".as_bytes());
    let len = buffer.len();
    assert_eq!(buffer.capacity(), len);
    {
        let _ = buffer.split();
        buffer.extend_from_slice("hello, world".as_bytes());
    }
    println!("buffer capacity:{}", buffer.capacity());
}

#[test]
fn bytes_advance() {
    let mut buffer = BytesMut::with_capacity(1024);
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.capacity(), 1024);
    unsafe {
        buffer.set_len(buffer.capacity());
    }
    for _ in 0..100 {
        buffer.advance(10);
        buffer.reserve(1024);
        println!("buffer.capacity() = {}", buffer.capacity());
    }
}

#[test]
fn bytes_capacity() {
    let mut buffer = BytesMut::with_capacity(1024);
    unsafe {
        buffer.set_len(100);
    }
    println!("buffer capacity is {}", buffer.capacity());
    let mut nb = buffer.split_off(100);
    println!("buffer capacity is {}", buffer.capacity());
    println!("new buffer capacity is {}", nb.capacity());
    nb.reserve(1024);
    println!("new buffer capacity is {}", nb.capacity());
    buffer.unsplit(nb);
    println!("buffer capacity is {}", buffer.capacity());
}
