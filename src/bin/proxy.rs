use async_std::net::UdpSocket;

use trojan::config::OPTIONS;

#[async_std::main]
async fn main() {
    let socket = UdpSocket::bind(&OPTIONS.local_addr).await.unwrap();
    trojan::aproxy::run().await;
}
