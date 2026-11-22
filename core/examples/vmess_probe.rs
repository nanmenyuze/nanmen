use nanmen_core::config::{Node, Target};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> io::Result<()> {
    let node = Node {
        name: "probe".into(),
        kind: "vmess".into(),
        server: std::env::var("VMESS_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        port: std::env::var("VMESS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(10808),
        method: Some(std::env::var("VMESS_SCY").unwrap_or_else(|_| "auto".into())),
        password: None,
        uuid: Some(
            std::env::var("VMESS_UUID")
                .unwrap_or_else(|_| "11111111-1111-1111-1111-111111111111".into()),
        ),
        sni: None,
        insecure: Some(
            std::env::var("VMESS_INSECURE")
                .map(|v| v == "1")
                .unwrap_or(false),
        ),
        tls: Some(
            std::env::var("VMESS_TLS")
                .map(|v| v == "1")
                .unwrap_or(false),
        ),
        ws_path: std::env::var("VMESS_WS_PATH").ok(),
        ws_host: std::env::var("VMESS_WS_HOST").ok(),
        flow: None,
        udp: Some(false),
    };
    let target_port = std::env::var("TARGET_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(19090);
    let target_domain = std::env::var("TARGET_DOMAIN").ok();
    let target = Target {
        ip: if target_domain.is_some() {
            "0.0.0.0".parse().unwrap()
        } else {
            "127.0.0.1".parse().unwrap()
        },
        port: target_port,
        domain: target_domain,
    };
    let mut s = nanmen_core::proto::vmess::connect(&node, target).await?;
    let payload: Vec<u8> = if std::env::var("PROBE_LARGE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        b"hello-vmess\n".repeat(4000)
    } else {
        b"hello-vmess\n".to_vec()
    };
    s.write_all(&payload).await?;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 16384];
    let res = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while got.len() < payload.len() {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        Ok::<(), io::Error>(())
    })
    .await;
    for item in nanmen_core::logging::dump_since(0) {
        eprintln!("[{}] {} {}", item.level, item.tag, item.msg);
    }
    res.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timeout"))??;
    println!(
        "RECV {} bytes {}",
        got.len(),
        String::from_utf8_lossy(&got[..got.len().min(40)])
    );
    Ok(())
}
