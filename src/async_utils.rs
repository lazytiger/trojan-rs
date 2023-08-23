use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn copy<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    mut read: R,
    mut write: W,
    message: String,
    timeout: u64,
) {
    let mut buffer = vec![0u8; 4096];

    while let Ok(Ok(n)) = tokio::time::timeout(
        Duration::from_secs(timeout),
        read.read(buffer.as_mut_slice()),
    )
    .await
    {
        if n > 0 {
            if let Ok(Ok(())) = tokio::time::timeout(
                Duration::from_secs(10),
                write.write_all(&buffer.as_slice()[..n]),
            )
            .await
            {
                continue;
            } else {
                log::error!("{} write failed", message);
            }
        }
        break;
    }
    log::warn!("{} read failed", message);
    let _ = write.shutdown().await;
}
