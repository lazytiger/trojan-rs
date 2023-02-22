use std::{
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use surge_ping::{Client, ConfigBuilder, IcmpPacket, PingIdentifier, PingSequence};
use tokio::runtime::{Builder, Runtime};

fn main() {
    let handle = std::thread::spawn(move || {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let config = ConfigBuilder::default()
                .bind("192.168.3.5:0".parse().unwrap())
                .build();
            let client = Client::new(&config).unwrap();
            let mut pinger = client
                .pinger("184.28.161.165".parse().unwrap(), PingIdentifier(1))
                .await;
            pinger.timeout(Duration::from_millis(999));
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            for i in 0..100 {
                ticker.tick().await;
                match pinger
                    .ping(PingSequence(i), "Hello, world".as_bytes())
                    .await
                {
                    Ok((IcmpPacket::V4(packet), duration)) => {
                        println!(
                            "No.{}:{} bytes from {}: icmp_seq={} ttl={} time={:0.2?}",
                            i,
                            packet.get_size(),
                            packet.get_source(),
                            packet.get_sequence(),
                            packet.get_ttl(),
                            duration
                        );
                    }
                    Ok((IcmpPacket::V6(packet), duration)) => {
                        println!(
                            "No.{}:{} bytes from {}: icmp_seq={} ttl={} time={:0.2?}",
                            i,
                            packet.get_size(),
                            packet.get_source(),
                            packet.get_sequence(),
                            packet.get_max_hop_limit(),
                            duration
                        );
                    }
                    Err(err) => {
                        println!("No.{}: {} ping {}", i, pinger.host, err);
                    }
                }
            }
            println!("[+] {} done", pinger.host);
        })
    });
    handle.join().unwrap();
}
