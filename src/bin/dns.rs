use std::net::{SocketAddr, UdpSocket};

fn main() {
    let local: SocketAddr = "169.254.79.165:0".parse().unwrap();
    let remote: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let socket = UdpSocket::bind(local).unwrap();
    socket.connect(remote).unwrap();
    socket.send(&[1, 2, 3, 4]).unwrap();
    let mut buffer = vec![0u8; 1024];
    let length = socket.recv(buffer.as_mut_slice()).unwrap();
    println!("length:{}", length);
}
