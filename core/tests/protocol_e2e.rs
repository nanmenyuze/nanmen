//! M4 协议验收：用本地受控服务端完成建立、双向传输、失败与重连。
//! 这些服务端只实现客户端实际发送的握手字节，不引入外网依赖。

use nanmen_core::config::{Node, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn node(kind: &str, port: u16) -> Node {
    Node {
        name: format!("{}-test", kind),
        kind: kind.into(),
        server: "127.0.0.1".into(),
        port,
        method: if kind == "vless" { Some("tcp".into()) } else { None },
        password: if kind == "trojan" { Some("pass".into()) } else { None },
        uuid: if kind == "vless" {
            Some("11111111-2222-3333-4444-555555555555".into())
        } else {
            None
        },
        sni: None,
        insecure: None,
        tls: Some(false),
        ws_path: None,
        ws_host: None,
        flow: None,
        udp: None,
    }
}

fn target() -> Target {
    // Trojan/VLESS 这里用 IPv4 目标，便于本地服务端精确读取握手头。
    Target { ip: "203.0.113.9".parse().unwrap(), port: 443, domain: None }
}

fn domain_target() -> Target {
    Target { ip: "203.0.113.9".parse().unwrap(), port: 443, domain: Some("example.com".into()) }
}

async fn echo_loop(mut sock: tokio::net::TcpStream) {
    let mut buf = [0u8; 64];
    loop {
        match sock.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if sock.write_all(&buf[..n]).await.is_err() { break; }
            }
        }
    }
}

async fn roundtrip(mut stream: nanmen_core::outbound::BoxStream, expect_hello: bool) {
    if expect_hello {
        let mut hello = [0u8; 5];
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut hello))
            .await.unwrap().unwrap();
        assert_eq!(&hello, b"hello");
    }
    stream.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut pong))
        .await.unwrap().unwrap();
    assert_eq!(&pong, b"ping");
}

#[tokio::test]
async fn trojan_plain_connects_roundtrip_and_reconnects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // 56 字节 SHA224 hex + CRLF + CONNECT + IPv4 目标 + CRLF
                let mut head = [0u8; 56 + 2 + 1 + 1 + 4 + 2 + 2];
                sock.read_exact(&mut head).await.unwrap();
                sock.write_all(b"hello").await.unwrap();
                echo_loop(sock).await;
            });
        }
    });
    let client = node("trojan", addr.port());
    roundtrip(nanmen_core::proto::trojan::connect(&client, target()).await.unwrap(), true).await;
    roundtrip(nanmen_core::proto::trojan::connect(&client, target()).await.unwrap(), true).await;
    // 端口关闭后必须报错，而不是假装连接成功。
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    assert!(nanmen_core::proto::trojan::connect(&node("trojan", dead_port), target()).await.is_err());
    server.abort();
}

#[tokio::test]
async fn vless_plain_connects_roundtrip_and_reconnects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // version 1 + UUID 16 + addons 1 + cmd 1 + IPv4 目标 7 = 26
                let mut head = [0u8; 26];
                sock.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0], 0);
                sock.write_all(&[0u8, 0u8]).await.unwrap();
                echo_loop(sock).await;
            });
        }
    });
    let client = node("vless", addr.port());
    roundtrip(nanmen_core::proto::vless::connect(&client, target()).await.unwrap(), false).await;
    roundtrip(nanmen_core::proto::vless::connect(&client, target()).await.unwrap(), false).await;
    let mut bad = node("vless", addr.port());
    bad.uuid = Some("bad-uuid".into());
    assert!(nanmen_core::proto::vless::connect(&bad, target()).await.is_err());
    server.abort();
}

#[tokio::test]
async fn socks5_connects_roundtrip_and_reconnects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut greet = [0u8; 3];
                sock.read_exact(&mut greet).await.unwrap();
                sock.write_all(&[0x05, 0x00]).await.unwrap();
                // CONNECT + 域名地址：ATYP 1 + len 1 + 11 + port 2，共 17 字节
                let mut req = [0u8; 3 + 1 + 1 + 11 + 2];
                sock.read_exact(&mut req).await.unwrap();
                // 成功应答：IPv4 0.0.0.0:0
                sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
                echo_loop(sock).await;
            });
        }
    });
    let client = node("socks5", addr.port());
    roundtrip(nanmen_core::proto::socks::connect_socks5(&client, domain_target()).await.unwrap(), false).await;
    roundtrip(nanmen_core::proto::socks::connect_socks5(&client, domain_target()).await.unwrap(), false).await;
    server.abort();
}

#[tokio::test]
async fn socks5_udp_associate_is_separate_and_roundtrips() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut greet = [0u8; 3];
        sock.read_exact(&mut greet).await.unwrap();
        sock.write_all(&[0x05, 0x00]).await.unwrap();
        let mut req = [0u8; 10];
        sock.read_exact(&mut req).await.unwrap();
        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        reply.extend_from_slice(&relay_addr.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap().octets());
        reply.extend_from_slice(&relay_addr.port().to_be_bytes());
        sock.write_all(&reply).await.unwrap();
        // 控制连接必须保持，UDP relay 单独收发包。
        let mut buf = [0u8; 2048];
        loop {
            match relay.recv_from(&mut buf).await {
                Ok((n, peer)) => { let _ = relay.send_to(&buf[..n], peer).await; }
                Err(_) => break,
            }
        }
    });
    let client = node("socks5", addr.port());
    let s = nanmen_core::proto::socks::udp_associate(&client).await.unwrap();
    // RSV 00 00 + FRAG 00 + IPv4 目标 + payload
    let mut packet = vec![0u8, 0u8, 0u8, 0x01, 127, 0, 0, 1, 9, 9];
    packet.extend_from_slice(b"udp-ping");
    s.socket.send(&packet).await.unwrap();
    let mut got = [0u8; 2048];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.socket.recv(&mut got))
        .await.unwrap().unwrap();
    assert!(got[..n].ends_with(b"udp-ping"));
    server.abort();
}
