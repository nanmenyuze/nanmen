//! HTTP/2 MITM：ALPN 协商到 h2 后，按 stream 解析请求头/URL；
//! 命中拒绝规则时用 HTTP/2 trailers 的 `grpc-status` 拒绝 gRPC，
//! 其余请求转发到真实服务器的 h2 连接。请求体与响应体按 stream 流式搬运。

use crate::config::Target;
use crate::engine::Action;
use crate::logging;
use crate::netstack::Ctx;
use crate::outbound;
use super::{MitmState, RewriteAction, RewriteRule, ScriptMessage, ScriptPhase};
use super::loon::{self, BodyOp, HeaderOp};
use super::http1::{BodyKind, RequestHead};
use bytes::Bytes;
use ::h2::client::SendRequest;
use ::h2::server::SendResponse;
use ::h2::{RecvStream, SendStream};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, Version};
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

const H2_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 客户端 h2 preface 等待：App 连接池常预热多条 TLS 但延迟启用，给足空闲窗口（真实服务器 60s+）。
const H2_CLIENT_PREFACE_TIMEOUT: Duration = Duration::from_secs(60);
const H2_STREAM_TIMEOUT: Duration = Duration::from_secs(300);
const H2_SEND_CHUNK: usize = 16 * 1024;

/// 判断请求是否 gRPC：content-type 以 application/grpc 开头。
pub fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase().starts_with("application/grpc"))
        .unwrap_or(false)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "expect"
    )
}

/// HTTP/2 规范只允许 `te: trailers`；其余 te 值会被上游拒绝。
/// 多个值中只要包含 trailers 就只保留 `te: trailers`，否则整段删除。
fn sanitize_te(headers: &mut HeaderMap) {
    let has_trailers = headers.get_all("te").iter().any(|v| {
        v.to_str()
            .ok()
            .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case("trailers")))
            .unwrap_or(false)
    });
    headers.remove("te");
    if has_trailers {
        headers.insert("te", HeaderValue::from_static("trailers"));
    }
}

fn url_for(host: &str, req: &Request<RecvStream>) -> String {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .filter(|p| !p.is_empty())
        .unwrap_or("/");
    format!("https://{}{}", host, path)
}

/// 按当前可用流控窗口发送 DATA：不能等窗口攒够整块再写，
/// 否则对端窗口小于 `H2_SEND_CHUNK` 时会互相等待（已有额度也用不上）。
/// 每次只发当前 `capacity` 允许的部分，发完再补充下一段预留额度。
async fn send_chunked(send: &mut SendStream<Bytes>, data: Bytes) -> Result<(), String> {
    let mut remaining = data;
    while !remaining.is_empty() {
        let capacity = send.capacity();
        if capacity == 0 {
            let want = remaining.len().min(H2_SEND_CHUNK);
            send.reserve_capacity(want);
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(format!("h2 发送流控失败: {}", e)),
                None => return Err("h2 发送流已关闭".into()),
            }
        }
        let n = capacity.min(remaining.len());
        send.send_data(remaining.slice(..n), false)
            .map_err(|e| format!("h2 DATA 发送失败: {}", e))?;
        remaining = remaining.slice(n..);
    }
    Ok(())
}

/// 建立一条 h2 上游连接；返回的 SendRequest 可克隆给同一连接上的多个 stream。
async fn connect_upstream(
    host: &str,
    target: &Target,
    action: &Action,
    ctx: &Arc<Ctx>,
    state: &Arc<MitmState>,
    conn_id: u64,
) -> Result<SendRequest<Bytes>, io::Error> {
    let raw = outbound::connect(
        action,
        &ctx.nodes_snapshot(),
        ctx.selected_snapshot().as_deref(),
        target.clone(),
        Some(&ctx.dns()),
    )
    .await?;
    let tls = outbound::tls_wrap_h2(raw, host, state.engine.upstream_insecure).await?;
    let (send, conn) = ::h2::client::handshake(tls)
        .await
        .map_err(|e| outbound::io_err(format!("h2 上游握手失败: {}", e)))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            logging::warn("mitm", format!("#{} h2 上游连接结束: {}", conn_id, e));
        }
    });
    Ok(send)
}

struct UpstreamSlot {
    send: Option<(SendRequest<Bytes>, u64)>,
    generation: u64,
}

/// 每条下游 h2 连接共享的上游连接槽：首个非拒绝流惰性建连，
/// 失败重试一次；连接断开时仅清掉同代连接，避免误伤其他流新建的连接。
struct UpstreamHandle {
    slot: tokio::sync::Mutex<UpstreamSlot>,
    target: Target,
    action: Action,
}

impl UpstreamHandle {
    fn target(&self) -> &Target {
        &self.target
    }

    fn action(&self) -> &Action {
        &self.action
    }

    fn new(target: Target, action: Action) -> Self {
        Self {
            slot: tokio::sync::Mutex::new(UpstreamSlot {
                send: None,
                generation: 0,
            }),
            target,
            action,
        }
    }

    async fn get(
        &self,
        host: &str,
        ctx: &Arc<Ctx>,
        state: &Arc<MitmState>,
        conn_id: u64,
    ) -> Result<(SendRequest<Bytes>, u64), String> {
        let mut slot = self.slot.lock().await;
        if let Some((send, generation)) = slot.send.as_ref() {
            return Ok((send.clone(), *generation));
        }
        let mut last_error = String::new();
        for attempt in 0..2 {
            let result = tokio::time::timeout(
                H2_CONNECT_TIMEOUT,
                connect_upstream(host, &self.target, &self.action, ctx, state, conn_id),
            )
            .await;
            match result {
                Ok(Ok(send)) => {
                    slot.generation = slot.generation.wrapping_add(1);
                    let generation = slot.generation;
                    slot.send = Some((send.clone(), generation));
                    return Ok((send, generation));
                }
                Ok(Err(e)) => last_error = e.to_string(),
                Err(_) => last_error = "连接超时".to_string(),
            }
            if attempt == 0 {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
        Err(format!("h2 上游连接失败（已重试 1 次）: {}", last_error))
    }

    async fn invalidate(&self, generation: u64) {
        let mut slot = self.slot.lock().await;
        if slot.send.as_ref().map(|(_, g)| *g) == Some(generation) {
            slot.send = None;
        }
    }
}

struct Responder {
    inner: SendResponse<Bytes>,
    sent: bool,
}

impl Responder {
    fn new(inner: SendResponse<Bytes>) -> Self {
        Self { inner, sent: false }
    }

    fn send(&mut self, response: Response<()>, end_of_stream: bool) -> Result<SendStream<Bytes>, String> {
        self.sent = true;
        self.inner
            .send_response(response, end_of_stream)
            .map_err(|e| format!("h2 响应头发送失败: {}", e))
    }

    fn reset(&mut self, reason: ::h2::Reason) {
        self.inner.send_reset(reason);
    }
}

/// 服务端入口：TLS 已协商 h2，逐 stream 处理；每条 stream 独立任务，允许并发。
pub async fn serve<S>(
    tls: TlsStream<S>,
    host: String,
    target: Target,
    action: Action,
    ctx: Arc<Ctx>,
    state: Arc<MitmState>,
    conn_id: u64,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_with_preface_timeout(tls, host, target, action, ctx, state, conn_id, H2_CLIENT_PREFACE_TIMEOUT).await
}

/// 可指定客户端 preface 等待时长的入口（测试用短超时；生产 serve 用 60s）。
pub async fn serve_with_preface_timeout<S>(
    tls: TlsStream<S>,
    host: String,
    target: Target,
    action: Action,
    ctx: Arc<Ctx>,
    state: Arc<MitmState>,
    conn_id: u64,
    preface_timeout: Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = match tokio::time::timeout(preface_timeout, ::h2::server::handshake(tls)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return Err(outbound::io_err(format!("h2 服务端握手失败: {}", e))),
        Err(_) => {
            // 客户端完成 TLS 但迟迟未发 h2 preface：多为连接池预热/备用连接。
            // 按空闲连接安静回收，不当错误 warn（避免日志噪声与误报）。
            logging::info("mitm", format!("#{} {} h2 空闲连接未启用，回收", conn_id, host));
            return Ok(());
        }
    };

    let upstream = Arc::new(UpstreamHandle::new(target, action));

    while let Some(next) = conn.accept().await {
        let (req, respond) = match next {
            Ok(v) => v,
            Err(e) => {
                logging::warn("mitm", format!("#{} {} h2 stream 接收失败: {}", conn_id, host, e));
                continue;
            }
        };
        let host = host.clone();
        let ctx = ctx.clone();
        let state = state.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let mut responder = Responder::new(respond);
            if let Err(e) = handle_stream(
                req,
                &mut responder,
                &host,
                &ctx,
                &state,
                upstream,
                conn_id,
            )
            .await
            {
                logging::warn("mitm", format!("#{} {} h2 stream 失败: {}", conn_id, host, e));
                if !responder.sent {
                    let _ = send_status(&mut responder, 502);
                } else {
                    responder.reset(::h2::Reason::INTERNAL_ERROR);
                }
            }
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    req: Request<RecvStream>,
    responder: &mut Responder,
    host: &str,
    ctx: &Arc<Ctx>,
    state: &Arc<MitmState>,
    upstream_handle: Arc<UpstreamHandle>,
    conn_id: u64,
) -> Result<(), String> {
    let url = url_for(host, &req);
    let hits = state.engine.rules_for(&url);
    let is_head = req.method() == http::Method::HEAD;
    let path_for_log = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    if let Some(rule) = hits.iter().find(|r| {
        matches!(
            r.action,
            RewriteAction::Reject | RewriteAction::Reject200 | RewriteAction::RejectTinyGif
        )
    }) {
        let grpc = is_grpc(req.headers());
        let action = rule.action.clone();
        let path = http1_redact(req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/"));
        let body = req.into_body();
        if grpc {
            send_grpc_reject(responder)?;
        } else {
            send_http_reject(responder, &action)?;
        }
        ctx.stats.mitm_rejected.fetch_add(1, Ordering::Relaxed);
        logging::info(
            "mitm",
            format!(
                "#{} MITM {} {} -> h2 REJECT{}",
                conn_id,
                host,
                path,
                if grpc { " (grpc trailers)" } else { "" }
            ),
        );
        // 拒绝后客户端可能还在发请求体；异步排空，避免连接流控窗口被占住。
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(10), drain(body)).await;
        });
        return Ok(());
    }

    let body_rules: Vec<&RewriteRule> = hits
        .iter()
        .filter(|r| r.action == RewriteAction::Body)
        .copied()
        .collect();

    let mut rh = RequestHead {
        method: req.method().to_string(),
        path: req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string(),
        headers: req
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
            .collect(),
        keep_alive: true,
        body: BodyKind::None,
    };
    for r in hits.iter().filter(|r| r.action == RewriteAction::Header) {
        super::http1::set_header(&mut rh.headers, &r.header_field, &r.replacement);
    }
    let loon_hits = state.engine.loon_rules_for(&url);
    let plan = super::plan_loon_request(
        &loon_hits,
        host,
        upstream_handle.target(),
        &mut rh,
    );
    let script_url = format!("https://{}{}", plan.host, rh.path);
    let request_scripts = state.engine.scripts.has_phase(&script_url, ScriptPhase::Request);
    let script_needs_body = request_scripts && state.engine.scripts.needs_request_body(&script_url);
    if let Some(term) = &plan.terminal {
        send_terminal(responder, term, &plan.response_headers)?;
        ctx.stats.mitm_rejected.fetch_add(1, Ordering::Relaxed);
        logging::info(
            "mitm",
            format!("#{} MITM {} {} -> h2 Loon 本地响应", conn_id, host, http1_redact(&path_for_log)),
        );
        let body = req.into_body();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(10), drain(body)).await;
        });
        return Ok(());
    }

    // 复制请求头，剔除 HTTP/2 禁止的连接级头；Surge/Loon 头部规则已写入 rh.headers。
    let mut headers = HeaderMap::new();
    for (name, value) in &rh.headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else { continue };
        let Ok(value) = HeaderValue::from_str(value) else { continue };
        headers.insert(name, value);
    }
    headers.remove(http::header::HOST);
    for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "expect"] {
        headers.remove(name);
    }
    sanitize_te(&mut headers);

    let mut request_body = req.into_body();
    let end = request_body.is_end_stream();
    let encoded_request = super::http1::get_header(&rh.headers, "content-encoding")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !v.is_empty() && v != "identity"
        })
        .unwrap_or(false);
    // 压缩请求体不猜测语义：没有 mock 时保留原样，跳过正文改写。
    let wants_body_work = plan.request_mock.is_some()
        || !plan.request_body_ops.is_empty()
        || script_needs_body;
    let pre_body = if wants_body_work && !(encoded_request && plan.request_mock.is_none()) {
        let limit = state.engine.body_limit;
        let original = if end {
            Vec::new()
        } else {
            match read_h2_body_limited(&mut request_body, limit).await {
                Ok(v) => v,
                Err(e) => {
                    logging::warn("mitm", format!("#{} {} h2 请求体改写失败: {}", conn_id, host, e));
                    send_status(responder, 413)?;
                    return Ok(());
                }
            }
        };
        let (body, changed) = if let Some(mock) = &plan.request_mock {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_str(&mock.content_type).map_err(|e| e.to_string())?,
            );
            (mock.body.clone(), true)
        } else {
            let refs: Vec<&BodyOp> = plan.request_body_ops.iter().collect();
            loon::apply_body_ops(&original, &refs, limit)
                .unwrap_or((original, false))
        };
        if changed {
            headers.remove(http::header::CONTENT_ENCODING);
            headers.remove(http::header::CONTENT_LENGTH);
            headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string()).map_err(|e| e.to_string())?,
            );
        }
        Some(body)
    } else {
        if encoded_request && !plan.request_body_ops.is_empty() {
            logging::info("mitm", format!("#{} {} h2 请求体带压缩编码，跳过 Loon 请求体改写", conn_id, host));
        }
        None
    };
    let mut pre_body = pre_body;
    if request_scripts {
        if script_needs_body && pre_body.is_none() {
            logging::info(
                "mitm",
                format!("#{} {} h2 脚本需要正文但正文超限/带编码，跳过请求脚本", conn_id, host),
            );
        } else {
            let body_now = pre_body.as_deref().unwrap_or(&[]);
            let msg_in = super::request_script_message(&script_url, &rh, body_now);
            let batch = state.run_scripts(ScriptPhase::Request, &script_url, &msg_in).await;
            if !batch.errors.is_empty() {
                logging::warn(
                    "mitm",
                    format!("#{} h2 请求脚本 {} 条，问题: {}", conn_id, batch.matched, batch.errors.join("; ")),
                );
            }
            if batch.short_circuit {
                send_script_h2(responder, &batch.message, is_head).await?;
                ctx.stats.mitm_rewritten.fetch_add(1, Ordering::Relaxed);
                logging::info(
                    "mitm",
                    format!("#{} MITM {} {} -> h2 脚本本地响应 {}", conn_id, host, http1_redact(&path_for_log), batch.message.status),
                );
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(10), drain(request_body)).await;
                });
                return Ok(());
            }
            let mut rh_try = rh.clone();
            match super::apply_request_script(&mut rh_try, &batch.message, &plan.host, &script_url) {
                Ok(changed) => {
                    rh = rh_try;
                    if changed {
                        pre_body = Some(batch.message.body_bytes().to_vec());
                        headers.clear();
                        for (name, value) in &rh.headers {
                            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else { continue };
                            let Ok(value) = HeaderValue::from_str(value) else { continue };
                            headers.insert(name, value);
                        }
                        headers.remove(http::header::HOST);
                        for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "expect"] {
                            headers.remove(name);
                        }
                        sanitize_te(&mut headers);
                        ctx.stats.mitm_rewritten.fetch_add(1, Ordering::Relaxed);
                        logging::info(
                            "mitm",
                            format!("#{} MITM {} {} -> 请求脚本已修改", conn_id, host, http1_redact(&path_for_log)),
                        );
                    }
                }
                Err(e) => {
                    logging::warn("mitm", format!("#{} h2 请求脚本结果丢弃: {}", conn_id, e));
                }
            }
        }
    }
    let wire_end = end && pre_body.is_none();

    // URL 改写后必须以 plan.host + 改写后的 path 为准；不能继续复用
    // 客户端原始 :scheme/:authority，否则跨域改写只改了本地变量、线上仍打旧域名。
    let uri: http::Uri = format!("https://{}{}", plan.host, rh.path)
        .parse()
        .map_err(|e| format!("h2 请求 URI 构造失败: {}", e))?;
    let method = http::Method::from_bytes(rh.method.as_bytes())
        .map_err(|e| format!("h2 请求方法非法: {}", e))?;

    // 请求体动作可能改了 Content-Type/Content-Length，必须在读取后再构造上游请求头。
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_2);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) || name == http::header::HOST {
            continue;
        }
        builder = builder.header(name, value);
    }
    let out_req = builder
        .body(())
        .map_err(|e| format!("h2 上游请求构造失败: {}", e))?;

    let effective_handle = if plan.host != host || plan.target.port != upstream_handle.target().port {
        Arc::new(UpstreamHandle::new(plan.target.clone(), upstream_handle.action().clone()))
    } else {
        upstream_handle.clone()
    };
    let (mut upstream, mut upstream_generation) =
        match effective_handle.get(&plan.host, ctx, state, conn_id).await {
            Ok(v) => v,
            Err(e) => {
                logging::warn(
                    "mitm",
                    format!("#{} {} h2 上游不可用: {}", conn_id, host, e),
                );
                send_status(responder, 502)?;
                tokio::spawn(async move {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(10), drain(request_body)).await;
                });
                return Ok(());
            }
        };

    let retry_req = out_req.clone();
    let (response_future, mut upstream_body) = match upstream.send_request(out_req, wire_end) {
        Ok(v) => v,
        Err(e) => {
            logging::warn(
                "mitm",
                format!("#{} {} h2 上游请求失败，重连后重试: {}", conn_id, host, e),
            );
            effective_handle.invalidate(upstream_generation).await;
            let (mut retry_upstream, retry_generation) =
                effective_handle.get(&plan.host, ctx, state, conn_id).await?;
            upstream_generation = retry_generation;
            retry_upstream
                .send_request(retry_req, wire_end)
                .map_err(|e2| format!("h2 上游请求重试失败: {}", e2))?
        }
    };

    // 请求上传与上游响应必须并发：半双工客户端/双向 gRPC 可能先发一条消息，
    // 等服务端回话后才继续发送；若先等上传结束再读响应，两边会互相等待。
    // 请求体已被 Loon 改写时正文已在内存里，直接写完再读响应即可。
    let mut upload_task = if let Some(body) = pre_body.clone() {
        if !body.is_empty() {
            send_chunked(&mut upstream_body, Bytes::from(body)).await?;
            upstream_body
                .send_data(Bytes::new(), true)
                .map_err(|e| format!("h2 请求体结束失败: {}", e))?;
        }
        None
    } else if end {
        None
    } else {
        Some(tokio::spawn(forward_request_body(request_body, upstream_body)))
    };
    let mut upload_done = end || pre_body.is_some();
    let response = {
        tokio::pin!(response_future);
        loop {
            if upload_done {
                break match tokio::time::timeout(H2_STREAM_TIMEOUT, &mut response_future).await {
                    Ok(Ok(response)) => response,
                    Ok(Err(e)) => return Err(format!("h2 上游响应失败: {}", e)),
                    Err(_) => return Err("h2 上游响应超时".to_string()),
                };
            }
            let task = upload_task
                .as_mut()
                .ok_or_else(|| "h2 请求体转发任务丢失".to_string())?;
            tokio::select! {
                result = &mut response_future => {
                    match result {
                        Ok(response) => break response,
                        Err(e) => {
                            if let Some(t) = upload_task.take() {
                                t.abort();
                            }
                            return Err(format!("h2 上游响应失败: {}", e));
                        }
                    }
                }
                joined = task => {
                    upload_done = true;
                    match joined {
                        Ok(Ok(())) => continue,
                        Ok(Err(ForwardBodyError::Canceled)) => {
                            logging::info(
                                "mitm",
                                format!("#{} {} 客户端取消上传，保留共享上游连接", conn_id, host),
                            );
                            return Ok(());
                        }
                        Ok(Err(ForwardBodyError::Fatal(e))) => {
                            upstream_handle.invalidate(upstream_generation).await;
                            return Err(e);
                        }
                        Err(e) => {
                            upstream_handle.invalidate(upstream_generation).await;
                            return Err(format!("h2 请求体转发任务失败: {}", e));
                        }
                    }
                }
            }
        }
    };

    let copy_result = copy_response(
        response,
        responder,
        state,
        &body_rules,
        &plan.response_headers,
        &plan.response_body_ops,
        is_head,
        host,
        &path_for_log,
        conn_id,
        ctx,
    )
    .await;
    // 响应已结束（客户端可能还在上传）：停止继续向已结束的请求流写数据。
    if let Some(task) = upload_task.take() {
        task.abort();
    }
    copy_result?;
    Ok(())
}

#[derive(Debug)]
enum ForwardBodyError {
    Canceled,
    Fatal(String),
}

fn forward_body_read_error(e: ::h2::Error) -> ForwardBodyError {
    if e.is_reset() || matches!(e.reason(), Some(::h2::Reason::CANCEL)) {
        ForwardBodyError::Canceled
    } else {
        ForwardBodyError::Fatal(format!("h2 请求体读取失败: {}", e))
    }
}

async fn forward_request_body(
    mut body: RecvStream,
    mut send: SendStream<Bytes>,
) -> Result<(), ForwardBodyError> {
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(forward_body_read_error)?;
        let len = chunk.len();
        send_chunked(&mut send, chunk)
            .await
            .map_err(ForwardBodyError::Fatal)?;
        body.flow_control()
            .release_capacity(len)
            .map_err(|e| ForwardBodyError::Fatal(format!("h2 请求体流控失败: {}", e)))?;
    }
    if let Some(trailers) = body
        .trailers()
        .await
        .map_err(forward_body_read_error)?
    {
        send.send_trailers(trailers).map_err(|e| {
            ForwardBodyError::Fatal(format!("h2 请求 trailers 发送失败: {}", e))
        })?;
    } else {
        send.send_data(Bytes::new(), true).map_err(|e| {
            ForwardBodyError::Fatal(format!("h2 请求体结束失败: {}", e))
        })?;
    }
    Ok(())
}

async fn copy_response(
    response: Response<RecvStream>,
    responder: &mut Responder,
    state: &Arc<MitmState>,
    body_rules: &[&RewriteRule],
    response_header_ops: &[HeaderOp],
    response_body_ops: &[BodyOp],
    is_head: bool,
    host: &str,
    path: &str,
    conn_id: u64,
    ctx: &Arc<Ctx>,
) -> Result<(), String> {
    let (mut parts, mut body) = response.into_parts();
    {
        let mut hv: Vec<(String, String)> = parts
            .headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
            .collect();
        loon::apply_header_ops(&mut hv, &response_header_ops.iter().collect::<Vec<_>>());
        let mut hm = HeaderMap::new();
        for (k, v) in hv {
            let Ok(n) = HeaderName::from_bytes(k.as_bytes()) else { continue };
            let Ok(v) = HeaderValue::from_str(&v) else { continue };
            hm.append(n, v);
        }
        parts.headers = hm;
    }
    let limit = state.engine.body_limit;
    let ctype = header_str(&parts.headers, "content-type")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let encoding = header_str(&parts.headers, "content-encoding")
        .unwrap_or("")
        .trim()
        .to_string();
    let content_length = header_str(&parts.headers, "content-length")
        .and_then(|v| v.trim().parse::<usize>().ok());
    // gRPC 正文是二进制帧，不能按文本 Content-Type 判断；gRPC-Web 是另一套
    // 分帧/编码，先排除，避免误把 base64 或 web 帧当 protobuf。
    let grpc_body = ctype.starts_with("application/grpc")
        && !ctype.starts_with("application/grpc-web");
    let streaming = !grpc_body
        && (ctype.contains("text/event-stream")
            || ctype.starts_with("multipart/")
            || ctype.contains("application/x-ndjson"));
    let text_like = !streaming
        && !grpc_body
        && (ctype.is_empty()
            || ["json", "text", "html", "xml", "javascript"]
                .iter()
                .any(|t| ctype.contains(t)));
    // gRPC 只接受 Surge 的 protobuf 字段改写；Loon 的文本/JSON 动作不碰二进制帧。
    let script_url = format!("https://{}{}", host, path);
    let binary_response_scripts =
        state.engine.scripts.has_binary_phase(&script_url, ScriptPhase::Response);
    let response_scripts = (binary_response_scripts || !grpc_body)
        && state.engine.scripts.has_phase(&script_url, ScriptPhase::Response);
    let has_body_ops = !body_rules.is_empty()
        || (!grpc_body && !response_body_ops.is_empty())
        || response_scripts;
    let can_rewrite = has_body_ops
        && !is_head
        && (parts.status == http::StatusCode::OK || response_scripts)
        && (grpc_body || text_like)
        && content_length.map(|n| n <= limit).unwrap_or(true);
    // 多流同时改写会叠加「原文 + 解压 + 改写」三份缓冲区；额度不足时直接流式透传。
    let rewrite_permit = if can_rewrite {
        // gRPC 需要帧重组 + protobuf 递归，按完整三份上限预留；
        // 普通文本响应按实际未压缩长度预留，允许更多小响应并行。
        let reservation = if grpc_body {
            limit.saturating_mul(super::REWRITE_BUFFER_COPIES)
        } else {
            rewrite_reservation(content_length, &encoding, limit)
        };
        state.rewrite_budget.try_acquire(reservation)
    } else {
        None
    };
    let can_rewrite = can_rewrite && rewrite_permit.is_some();
    if !can_rewrite {
        let head = response_head(parts.status, &parts.headers)?;
        let mut send = responder.send(head, false)?;
        stream_response_body(body, &mut send).await?;
        return Ok(());
    }

    // DATA 帧重组：只对命中 body 规则的小响应缓冲，超过 limit 立即
    // 回退为「已收原始字节 + 剩余流式转发」，不把正文读进无界内存。
    let mut raw = Vec::new();
    let mut overflow = false;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| format!("h2 响应体读取失败: {}", e))?;
        let len = chunk.len();
        let next = raw.len().saturating_add(len);
        raw.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(len)
            .map_err(|e| format!("h2 响应体流控失败: {}", e))?;
        if next > limit {
            overflow = true;
            break;
        }
    }
    if overflow {
        // 已决定回退流式透传，立即释放改写额度，别让长响应占着预算。
        drop(rewrite_permit);
        let head = response_head(parts.status, &parts.headers)?;
        let mut send = responder.send(head, false)?;
        send_chunked(&mut send, Bytes::from(raw)).await?;
        stream_response_body(body, &mut send).await?;
        return Ok(());
    }

    let trailers = body
        .trailers()
        .await
        .map_err(|e| format!("h2 响应 trailers 读取失败: {}", e))?;
    let (mut new_body, mut changed, grpc_rewrite) = if grpc_body {
        // gRPC：帧头 + protobuf wire format 递归改写字符串字段；压缩帧不碰。
        match super::grpc::rewrite_grpc_body(&raw, body_rules, limit) {
            Some((body, changed)) => (body, changed, true),
            None => {
                drop(rewrite_permit);
                let head = response_head(parts.status, &parts.headers)?;
                let mut send = responder.send(head, false)?;
                send_buffered(&mut send, Bytes::from(raw), trailers).await?;
                return Ok(());
            }
        }
    } else {
        // 普通文本响应：解压 + 复用 rewrite 引擎。br/zstd 或解压超限时原样透传。
        let plain = match super::http1::decode_content_limited(&raw, &encoding, limit) {
            Some(v) => v,
            None => {
                drop(rewrite_permit);
                let head = response_head(parts.status, &parts.headers)?;
                let mut send = responder.send(head, false)?;
                send_buffered(&mut send, Bytes::from(raw), trailers).await?;
                return Ok(());
            }
        };
        let surge_out = if body_rules.is_empty() {
            Some((plain.clone(), false))
        } else {
            super::rewrite::apply_body_rules_limited(&plain, body_rules, limit)
        };
        let loon_out = if response_body_ops.is_empty() {
            Some((surge_out.as_ref().map(|(b, _)| b.clone()).unwrap_or_default(), false))
        } else {
            let base = surge_out.as_ref().map(|(b, _)| b.as_slice()).unwrap_or(&plain);
            loon::apply_body_ops(base, &response_body_ops.iter().collect::<Vec<_>>(), limit)
        };
        let (new_body, loon_changed) = match loon_out {
            Some(v) => v,
            None => {
                drop(rewrite_permit);
                let head = response_head(parts.status, &parts.headers)?;
                let mut send = responder.send(head, false)?;
                send_buffered(&mut send, Bytes::from(raw), trailers).await?;
                return Ok(());
            }
        };
        let changed = surge_out.map(|(_, c)| c).unwrap_or(false) || loon_changed;
        (new_body, changed, false)
    };
    let mut status_out = parts.status;
    let mut script_headers = parts.headers.clone();
    if response_scripts {
        let msg_in = super::response_script_message(
            &script_url,
            status_out.as_u16(),
            &script_headers
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
                .collect::<Vec<_>>(),
            &new_body,
        );
        let batch = state.run_scripts(ScriptPhase::Response, &script_url, &msg_in).await;
        if !batch.errors.is_empty() {
            logging::warn(
                "mitm",
                format!("#{} h2 响应脚本 {} 条，问题: {}", conn_id, batch.matched, batch.errors.join("; ")),
            );
        }
        if batch.matched > 0 && batch.message.body_len() <= limit {
            let body_bytes = batch.message.body_bytes().to_vec();
            if body_bytes != new_body {
                new_body = body_bytes;
                changed = true;
            }
            if batch.message.status >= 100 && batch.message.status <= 599 {
                if let Ok(st) = http::StatusCode::from_u16(batch.message.status) {
                    if st != status_out {
                        status_out = st;
                        changed = true;
                    }
                }
            }
            let mut hm = HeaderMap::new();
            for (k, v) in &batch.message.headers {
                let Ok(n) = HeaderName::from_bytes(k.as_bytes()) else { continue };
                let Ok(v) = HeaderValue::from_str(v) else { continue };
                hm.append(n, v);
            }
            if hm != script_headers {
                script_headers = hm;
                changed = true;
            }
        } else if batch.matched > 0 {
            logging::warn(
                "mitm",
                format!("#{} 响应脚本输出 {} 字节超过上限，丢弃脚本结果", conn_id, batch.message.body_len()),
            );
        }
    }
    if !changed {
        drop(rewrite_permit);
        let head = response_head(status_out, &parts.headers)?;
        let mut send = responder.send(head, false)?;
        send_buffered(&mut send, Bytes::from(raw), trailers).await?;
        return Ok(());
    }

    let mut headers = script_headers;
    // gRPC 的压缩在每帧 flag 里，不能删 grpc-encoding/content-encoding；
    // 普通响应改写后正文已解压，必须移除 content-encoding。
    if grpc_rewrite {
        headers.remove(http::header::CONTENT_LENGTH);
    } else {
        for name in ["content-encoding", "content-length"] {
            headers.remove(name);
        }
    }
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&new_body.len().to_string())
            .map_err(|e| format!("h2 改写后 Content-Length 非法: {}", e))?,
    );
    let rewritten_len = new_body.len();
    let head = response_head(status_out, &headers)?;
    let mut send = responder.send(head, false)?;
    send_buffered(&mut send, Bytes::from(new_body), trailers).await?;
    ctx.stats.mitm_rewritten.fetch_add(1, Ordering::Relaxed);
    logging::info(
        "mitm",
        format!(
            "#{} MITM {} {} -> {} 改写 {} {}→{} 字节",
            conn_id,
            host,
            http1_redact(path),
            status_out.as_u16(),
            if grpc_rewrite { "gRPC body" } else { "h2" },
            raw.len(),
            rewritten_len
        ),
    );
    Ok(())
}

/// 一条流改写期间最坏占用三份正文缓冲（原文、解压结果、改写结果）。
/// 已知未压缩长度时按实际长度的三倍预留，允许更多小响应并行；
/// 压缩响应/未知长度按 `body_limit` 的三倍预留，避免解压膨胀突破预算。
fn rewrite_reservation(content_length: Option<usize>, encoding: &str, limit: usize) -> usize {
    let full = limit.saturating_mul(super::REWRITE_BUFFER_COPIES);
    let identity = encoding.trim().is_empty()
        || encoding.trim().eq_ignore_ascii_case("identity");
    if identity {
        content_length
            .filter(|n| *n > 0)
            .map(|n| {
                n.saturating_mul(super::REWRITE_BUFFER_COPIES)
                    .min(full)
            })
            .unwrap_or(full)
    } else {
        full
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn response_head(
    status: http::StatusCode,
    headers: &HeaderMap,
) -> Result<Response<()>, String> {
    let mut builder = Response::builder().status(status).version(Version::HTTP_2);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|e| format!("h2 客户端响应构造失败: {}", e))
}

async fn send_buffered(
    send: &mut SendStream<Bytes>,
    data: Bytes,
    trailers: Option<HeaderMap>,
) -> Result<(), String> {
    send_chunked(send, data).await?;
    if let Some(trailers) = trailers {
        send.send_trailers(trailers)
            .map_err(|e| format!("h2 响应 trailers 发送失败: {}", e))?;
    } else {
        send.send_data(Bytes::new(), true)
            .map_err(|e| format!("h2 响应体结束失败: {}", e))?;
    }
    Ok(())
}

async fn stream_response_body(
    mut body: RecvStream,
    send: &mut SendStream<Bytes>,
) -> Result<(), String> {
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| format!("h2 响应体读取失败: {}", e))?;
        let len = chunk.len();
        send_chunked(send, chunk).await?;
        body.flow_control()
            .release_capacity(len)
            .map_err(|e| format!("h2 响应体流控失败: {}", e))?;
    }
    let trailers = body
        .trailers()
        .await
        .map_err(|e| format!("h2 响应 trailers 读取失败: {}", e))?;
    send_buffered(send, Bytes::new(), trailers).await
}

async fn drain(mut body: RecvStream) {
    while let Some(Ok(chunk)) = body.data().await {
        let len = chunk.len();
        let _ = body.flow_control().release_capacity(len);
    }
}

fn send_terminal(
    responder: &mut Responder,
    term: &super::Terminal,
    header_ops: &[HeaderOp],
) -> Result<(), String> {
    use super::Terminal;
    if matches!(term, Terminal::Reject(super::RejectKind::Drop)) {
        // Loon `reject` = 直接断开；h2 用 RST_STREAM 终止该流，不伪造 204。
        responder.reset(h2::Reason::CANCEL);
        return Ok(());
    }
    let (status, reason, mut headers, body): (u16, _, HeaderMap, Vec<u8>) = match term {
        Terminal::Reject(kind) => match kind {
            super::RejectKind::Drop => unreachable!(),
            super::RejectKind::Status200 => (200, "", HeaderMap::new(), Vec::new()),
            super::RejectKind::TinyGif => {
                let mut h = HeaderMap::new();
                h.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("image/gif"));
                (200, "", h, super::http1::TINY_GIF.to_vec())
            }
            super::RejectKind::JsonObject => {
                let mut h = HeaderMap::new();
                h.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                (200, "", h, b"{}".to_vec())
            }
            super::RejectKind::JsonArray => {
                let mut h = HeaderMap::new();
                h.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                (200, "", h, b"[]".to_vec())
            }
        },
        Terminal::Redirect { status, url } => {
            let mut h = HeaderMap::new();
            h.insert(http::header::LOCATION, HeaderValue::from_str(url).map_err(|e| e.to_string())?);
            (*status, "", h, Vec::new())
        }
        Terminal::Mock(spec) => {
            let mut h = HeaderMap::new();
            h.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_str(&spec.content_type).map_err(|e| e.to_string())?,
            );
            (spec.status, "", h, spec.body.clone())
        }
    };
    headers.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status != 204 {
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).map_err(|e| e.to_string())?,
        );
    }
    for op in header_ops {
        match op {
            HeaderOp::Add { name, value } => {
                let Ok(n) = HeaderName::from_bytes(name.as_bytes()) else { continue };
                let Ok(v) = HeaderValue::from_str(value) else { continue };
                headers.append(n, v);
            }
            HeaderOp::Del { name } => {
                headers.remove(name.as_str());
            }
            HeaderOp::Replace { name, value } => {
                let Ok(n) = HeaderName::from_bytes(name.as_bytes()) else { continue };
                let Ok(v) = HeaderValue::from_str(value) else { continue };
                headers.insert(n, v);
            }
            HeaderOp::ReplaceRegex { name, re, replacement } => {
                let Ok(n) = HeaderName::from_bytes(name.as_bytes()) else { continue };
                if let Some(v) = headers.get(&n).and_then(|v| v.to_str().ok()) {
                    let new = re.replace_all(v, replacement.as_str()).into_owned();
                    if let Ok(v) = HeaderValue::from_str(&new) {
                        headers.insert(n, v);
                    }
                }
            }
        }
    }
    let _ = reason;
    let response = Response::builder()
        .status(status)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|e| format!("h2 本地响应构造失败: {}", e))?;
    let mut send = responder.send(response, body.is_empty())?;
    if !body.is_empty() {
        send.send_data(Bytes::from(body), true)
            .map_err(|e| format!("h2 本地响应体发送失败: {}", e))?;
    }
    Ok(())
}

async fn read_h2_body_limited(body: &mut RecvStream, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| format!("h2 请求体读取失败: {}", e))?;
        let len = chunk.len();
        let next = out.len().saturating_add(len);
        out.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(len)
            .map_err(|e| format!("h2 请求体流控失败: {}", e))?;
        if next > limit {
            return Err("h2 请求体超过改写上限".into());
        }
    }
    Ok(out)
}

fn send_grpc_reject(responder: &mut Responder) -> Result<(), String> {
    let response = Response::builder()
        .status(200)
        .version(Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("cache-control", "no-store")
        .body(())
        .map_err(|e| format!("h2 gRPC 拒绝头构造失败: {}", e))?;
    let mut send = responder.send(response, false)?;
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("7"));
    trailers.insert(
        "grpc-message",
        HeaderValue::from_static("blocked by NamuDNS"),
    );
    send.send_trailers(trailers)
        .map_err(|e| format!("h2 gRPC trailers 发送失败: {}", e))?;
    Ok(())
}

fn send_http_reject(responder: &mut Responder, action: &RewriteAction) -> Result<(), String> {
    let (status, ctype, body): (u16, Option<&str>, &[u8]) = match action {
        RewriteAction::Reject => (204, None, &[]),
        RewriteAction::Reject200 => (200, None, &[]),
        RewriteAction::RejectTinyGif => (200, Some("image/gif"), super::http1::TINY_GIF),
        _ => (204, None, &[]),
    };
    let mut builder = Response::builder()
        .status(status)
        .version(Version::HTTP_2)
        .header("cache-control", "no-store");
    if let Some(ct) = ctype {
        builder = builder.header("content-type", ct);
    }
    if !body.is_empty() {
        builder = builder.header("content-length", body.len().to_string());
    }
    let response = builder
        .body(())
        .map_err(|e| format!("h2 拒绝头构造失败: {}", e))?;
    let end = body.is_empty();
    let mut send = responder.send(response, end)?;
    if !end {
        send.send_data(Bytes::copy_from_slice(body), true)
            .map_err(|e| format!("h2 拒绝体发送失败: {}", e))?;
    }
    Ok(())
}

async fn send_script_h2(
    responder: &mut Responder,
    msg: &ScriptMessage,
    is_head: bool,
) -> Result<(), String> {
    let status = if (100..=599).contains(&msg.status) { msg.status } else { 200 };
    let body = if is_head || status == 204 { Vec::new() } else { msg.body.as_bytes().to_vec() };
    let mut builder = Response::builder().status(status).version(Version::HTTP_2);
    for (name, value) in &msg.headers {
        let Ok(n) = HeaderName::from_bytes(name.as_bytes()) else { continue };
        if is_hop_by_hop(n.as_str()) { continue; }
        let Ok(v) = HeaderValue::from_str(value) else { continue };
        builder = builder.header(n, v);
    }
    builder = builder.header("cache-control", "no-store");
    if status != 204 {
        builder = builder.header("content-length", body.len().to_string());
    }
    let response = builder
        .body(())
        .map_err(|e| format!("h2 脚本响应头构造失败: {}", e))?;
    let end = body.is_empty();
    let mut send = responder.send(response, end)?;
    if !end {
        send_chunked(&mut send, Bytes::from(body)).await?;
        send.send_data(Bytes::new(), true)
            .map_err(|e| format!("h2 脚本响应体结束失败: {}", e))?;
    }
    Ok(())
}

fn send_status(responder: &mut Responder, status: u16) -> Result<(), String> {
    let response = Response::builder()
        .status(status)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|e| format!("h2 状态响应构造失败: {}", e))?;
    responder.send(response, true)?;
    Ok(())
}

fn http1_redact(path: &str) -> String {
    super::http1::redact_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grpc_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
        h
    }

    #[test]
    fn detects_grpc_content_type() {
        assert!(is_grpc(&grpc_headers()));
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc+proto"),
        );
        assert!(is_grpc(&h));
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!is_grpc(&h));
    }

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("Transfer-Encoding"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("te"));
    }

    #[test]
    fn te_header_only_keeps_trailers() {
        let mut h = HeaderMap::new();
        h.insert("te", HeaderValue::from_static("gzip"));
        sanitize_te(&mut h);
        assert!(h.get("te").is_none());

        h.insert("te", HeaderValue::from_static("gzip, trailers"));
        sanitize_te(&mut h);
        assert_eq!(h.get("te").unwrap(), "trailers");

        h.insert("te", HeaderValue::from_static("Trailers"));
        sanitize_te(&mut h);
        assert_eq!(h.get("te").unwrap(), "trailers");
    }
}
