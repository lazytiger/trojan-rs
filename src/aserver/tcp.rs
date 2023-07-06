use std::net::SocketAddr;

use tokio::{
    io::AsyncWriteExt,
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    spawn,
};

use tokio_rustls::{TlsServerReadHalf, TlsServerStream, TlsServerWriteHalf};

use crate::types::Result;

pub async fn start_tcp(
    mut source: TlsServerStream,
    target_addr: SocketAddr,
    data: Vec<u8>,
) -> Result<()> {
    let mut target = TcpStream::connect(target_addr).await?;
    if let Err(err) = target.write_all(data.as_slice()).await {
        let _ = target.shutdown().await;
        let _ = source.shutdown().await;
        log::error!("tcp send data to target failed:{}", err);
        return Ok(());
    }
    let (source_read, source_write) = source.into_split();
    let (target_read, target_write) = target.into_split();
    spawn(source_to_target(source_read, target_write));
    spawn(target_to_source(target_read, source_write));
    Ok(())
}

async fn source_to_target(mut read: TlsServerReadHalf, mut write: OwnedWriteHalf) {
    if let Err(err) = tokio::io::copy(&mut read, &mut write).await {
        log::error!("transfer data from source to target failed:{}", err);
    }
    let _ = write.shutdown().await;
    log::info!("tcp source to target exit");
}

async fn target_to_source(mut read: OwnedReadHalf, mut write: TlsServerWriteHalf) {
    if let Err(err) = tokio::io::copy(&mut read, &mut write).await {
        log::error!("transfer data from target to source failed:{}", err);
    }
    let _ = write.shutdown().await;
    log::info!("tcp target to source exit");
}
