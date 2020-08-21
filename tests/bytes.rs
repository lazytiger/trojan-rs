use bytes::BytesMut;

#[test]
fn bytes_memory() {
    let mut buffer = BytesMut::new();
    buffer.extend_from_slice("hello, world".as_bytes());
    let len = buffer.len();
    assert_eq!(buffer.capacity(), len);
    let new_buffer = buffer.split();
    buffer.clear();
    assert_eq!(buffer.capacity(), 0);
    assert_eq!(new_buffer.capacity(), new_buffer.len());
    buffer.extend_from_slice(new_buffer.as_ref());
    assert_eq!(buffer.capacity(), len);
}