use nanmen_core::mitm::ca::{system_cert_name, MitmCa};

/// 回归：CA 主题固定（CN=Namu DNS MITM CA, O=Namu DNS，rcgen 0.13.2 编码为 UTF8String），
/// 系统证书文件名必须恒为 d756baa7.0。KernelSU/Magisk 模块按此名注入；
/// 若升级 rcgen 导致 subject DER 编码变化，此测试会失败，提醒同步更新模块文件名。
#[test]
fn system_cert_name_is_stable() {
    let dir = std::env::temp_dir().join(format!("namu_ca_name_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_path = dir.join("ca.pem");
    let _ca = MitmCa::load_or_generate(ca_path.to_str().unwrap()).unwrap();
    let name = system_cert_name(ca_path.to_str().unwrap()).unwrap();
    assert_eq!(
        name, "d756baa7.0",
        "CA subject_hash_old 变化，需同步更新系统信任模块"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
