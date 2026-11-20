// 南门DNS 自写合成样本：验证 binary-body-mode 下的 Uint8Array 读写。
// 输入是一个最小的 gRPC 5 字节帧；脚本复制后修改第一个 payload 字节，
// 再通过 $done({ body }) 回写，供 Rust 验收测试断言原始字节没有走文本编解码。
const input = $response.body;
const out = new Uint8Array(input.length);
out.set(input);
out[5] = 0x2a;
$done({
    body: out,
    headers: { "grpc-encoding": "identity" }
});
