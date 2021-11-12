#[async_std::main]
async fn main() {
    trojan::aproxy::run_udp().await;
}
