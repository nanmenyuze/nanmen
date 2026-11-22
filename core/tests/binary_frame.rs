//! 自写二进制脚本回归：$response.body 以 Uint8Array 暴露，
//! 脚本按 gRPC 5 字节帧读取后通过 $done({body}) 回写原始字节。

use nanmen_core::script::{run_script, ScriptMessage, ScriptOptions, ScriptPhase};

#[test]
fn synthetic_binary_frame_roundtrip() {
    let src = include_str!("fixtures/binary-frame.js");
    // 合成 gRPC 帧：flag=0，长度=4，payload 为任意 4 字节。
    let payload = vec![0x3au8, 0x02, 0x1a, 0x00];
    let mut body = vec![0u8, 0, 0, 0, payload.len() as u8];
    body.extend_from_slice(&payload);
    let msg = ScriptMessage {
        url: "https://grpc.video.example.com/demo.View/View".into(),
        method: "POST".into(),
        status: 200,
        headers: vec![
            ("content-type".into(), "application/grpc".into()),
            ("grpc-encoding".into(), "identity".into()),
        ],
        body: String::from_utf8_lossy(&body).into_owned(),
        body_bytes: Some(body.clone()),
    };
    let out = run_script(
        src,
        ScriptPhase::Response,
        &msg,
        &ScriptOptions {
            binary_body_mode: true,
            timeout_ms: 10_000,
            ..Default::default()
        },
    );
    assert!(out.error.is_none(), "脚本报错: {:?}", out.error);
    let out_bytes = out.message.body_bytes();
    assert_eq!(out_bytes.len(), body.len());
    assert_eq!(out_bytes[0], 0, "输出帧必须保持未压缩");
    assert_eq!(out_bytes[5], 0x2a, "payload 的首字节应被脚本改写");
    assert!(out
        .message
        .headers
        .iter()
        .any(|(k, v)| k == "grpc-encoding" && v == "identity"));
}
