use bytes::BytesMut;

#[test]
fn bytes_memory() {
    let mut buffer = BytesMut::new();
    buffer.extend_from_slice("hello, world".as_bytes());
    let len = buffer.len();
    assert_eq!(buffer.capacity(), len);
    {
        let new_buffer = buffer.split();
        buffer.extend_from_slice("hello, world".as_bytes());
    }
    println!("buffer capacity:{}", buffer.capacity());
}