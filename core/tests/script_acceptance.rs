//! M6 脚本验收套件：以真实/公开样本形态覆盖请求、响应、异步网络、持久化、
//! 大数据与请求短路。对应 M6 任务书「真实授权或公开样本覆盖请求、响应、
//! 异步网络和持久化」验收项。全部走公开 run_script API，不依赖私有内部。

use nanmen_core::script::{run_script, ScriptMessage, ScriptOptions, ScriptPhase, ScriptStore};
use std::sync::Arc;

fn msg(url: &str, body: &str) -> ScriptMessage {
    ScriptMessage {
        url: url.into(),
        method: "GET".into(),
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.into(),
        body_bytes: None,
    }
}

/// 请求阶段脚本：改方法/URL/头/正文，$done({}) 保持已改值。
#[test]
fn request_phase_script_rewrites_method_headers_body() {
    let src = r#"
        $request.method = "POST";
        $request.headers["x-injected"] = "1";
        $request.body = JSON.stringify({ q: 1 });
        $done({});
    "#;
    let out = run_script(
        src,
        ScriptPhase::Request,
        &msg("https://api.example.com/v1", ""),
        &ScriptOptions::default(),
    );
    assert!(out.error.is_none(), "请求脚本报错: {:?}", out.error);
    assert_eq!(out.message.method, "POST");
    assert!(out
        .message
        .headers
        .iter()
        .any(|(k, v)| k == "x-injected" && v == "1"));
    assert_eq!(out.message.body, r#"{"q":1}"#);
}

/// 异步网络：async/await 包裹 $httpClient.get（本地受控服务端），续体完成后 $done。
#[test]
fn async_await_http_client_fetches_and_completes() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        let _ = s
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nnetwork");
    });
    let src = format!(
        r#"
        (async function () {{
            const data = await new Promise(function (resolve) {{
                $httpClient.get("http://{addr}/x", function (err, resp, d) {{ resolve(d); }});
            }});
            $done({{ body: "got:" + data }});
        }})();
    "#
    );
    let out = run_script(
        &src,
        ScriptPhase::Request,
        &msg("https://api.example.com/", ""),
        &ScriptOptions {
            allow_private_network: true,
            ..Default::default()
        },
    );
    assert!(out.error.is_none(), "async 网络脚本报错: {:?}", out.error);
    assert_eq!(out.message.body, "got:network");
    assert_eq!(out.http_calls, 1);
    assert_eq!(out.done_calls, 1);
}

/// 持久化：同一 store 跨两次执行 write→read 往返。
#[test]
fn persistent_store_roundtrip_across_runs() {
    let store = Arc::new(ScriptStore::new(""));
    let opts = ScriptOptions {
        store: Some(store.clone()),
        script_name: "acc".into(),
        ..Default::default()
    };
    let w = run_script(
        r#"$persistentStore.write("hello", "k"); $done({});"#,
        ScriptPhase::Response,
        &msg("https://x/", "{}"),
        &opts,
    );
    assert!(w.error.is_none());
    let r = run_script(
        r#"$done({ body: $persistentStore.read("k") });"#,
        ScriptPhase::Response,
        &msg("https://x/", "{}"),
        &opts,
    );
    assert!(r.error.is_none(), "读取报错: {:?}", r.error);
    assert_eq!(r.message.body, "hello");
}

/// 大数据：约 2 MiB 正文的 JSON 解析+过滤可完成，不 panic、不超时。
#[test]
fn large_body_json_filter_completes() {
    let item = r#"{"card_type":"cm_v2","card_goto":"ad_av","pad":"xxxxxxxxxxxxxxxxxxxx"}"#;
    let normal = r#"{"card_type":"small_cover_v10","card_goto":"video"}"#;
    let mut items = Vec::new();
    for i in 0..40000 {
        items.push(if i % 10 == 0 { item } else { normal });
    }
    let body = format!(r#"{{"data":{{"items":[{}]}}}}"#, items.join(","));
    assert!(body.len() > 1_500_000, "样本应 >1.5MB，实际 {}", body.len());
    let src = r#"
        var b = JSON.parse($response.body);
        b.data.items = b.data.items.filter(function (it) { return it.card_goto !== "ad_av"; });
        $done({ body: JSON.stringify(b) });
    "#;
    let out = run_script(
        src,
        ScriptPhase::Response,
        &msg("https://app.video.example.com/x/v2/feed/index", &body),
        &ScriptOptions {
            timeout_ms: 8000,
            ..Default::default()
        },
    );
    assert!(out.error.is_none(), "大数据脚本报错: {:?}", out.error);
    let v: serde_json::Value = serde_json::from_str(&out.message.body).unwrap();
    let n = v["data"]["items"].as_array().unwrap().len();
    assert_eq!(n, 36000, "应剔除 4000 条广告卡");
}

/// 请求短路：$done({response:{...}}) 生成本地响应，不再访问上游。
#[test]
fn request_short_circuit_generates_local_response() {
    let src = r#"$done({ response: { status: 200, headers: {"content-type":"text/plain"}, body: "mocked" } });"#;
    let out = run_script(
        src,
        ScriptPhase::Request,
        &msg("https://api.example.com/ad", ""),
        &ScriptOptions::default(),
    );
    assert!(out.error.is_none(), "短路报错: {:?}", out.error);
    assert!(out.short_circuit_response);
    assert_eq!(out.message.body, "mocked");
    assert_eq!(out.message.status, 200);
}
