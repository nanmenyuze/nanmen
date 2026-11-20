#!/usr/bin/env bash
set -euo pipefail

# 需要 rustup 已安装 aarch64-linux-android / armv7-linux-androideabi target。
# NDK 路径不再硬编码：优先环境变量，其次 local.properties / ANDROID_HOME，最后扫描常见目录。
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

find_ndk() {
  for cand in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    [ -n "$cand" ] && [ -d "$cand" ] && { echo "$cand"; return 0; }
  done
  local sdk=""
  if [ -f "$ROOT/local.properties" ]; then
    sdk="$(sed -n 's/^sdk\.dir=//p' "$ROOT/local.properties" | head -1)"
  fi
  sdk="${sdk:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}}"
  if [ -d "$sdk/ndk" ]; then
    local latest
    latest="$(ls -1 "$sdk/ndk" 2>/dev/null | sort -V | tail -1)"
    [ -n "$latest" ] && { echo "$sdk/ndk/$latest"; return 0; }
  fi
  return 1
}

NDK="$(find_ndk || true)"
if [ -z "$NDK" ] || [ ! -d "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
  echo "找不到 Android NDK：请设置 ANDROID_NDK_HOME，或在 local.properties 写入 sdk.dir" >&2
  exit 1
fi
HOST_TAG="$(basename "$(ls -d "$NDK"/toolchains/llvm/prebuilt/* | head -1)")"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
STRIP="$TOOLCHAIN/llvm-strip"
export PATH="$HOME/.cargo/bin:$TOOLCHAIN:$PATH"
export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"
export AR_armv7_linux_androideabi="$TOOLCHAIN/llvm-ar"
# 链接器全部由 NDK 路径推导，不依赖 .cargo/config.toml 里的绝对路径；换机器/换 NDK 都能编。
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android24-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$TOOLCHAIN/armv7a-linux-androideabi24-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-Clink-arg=-Wl,-z,max-page-size=16384"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="-Clink-arg=-Wl,-z,max-page-size=16384"
export CC_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android24-clang"
export CC_armv7_linux_androideabi="$TOOLCHAIN/armv7a-linux-androideabi24-clang"

cd "$ROOT/core"
cargo build --release --locked --target aarch64-linux-android
cargo build --release --locked --target armv7-linux-androideabi

"$STRIP" --strip-unneeded target/aarch64-linux-android/release/libnanmen_core.so
"$STRIP" --strip-unneeded target/armv7-linux-androideabi/release/libnanmen_core.so
cp target/aarch64-linux-android/release/libnanmen_core.so "$ROOT/app/src/main/jniLibs/arm64-v8a/libnanmen_core.so"
cp target/armv7-linux-androideabi/release/libnanmen_core.so "$ROOT/app/src/main/jniLibs/armeabi-v7a/libnanmen_core.so"

# 产物与「源码内容哈希」一起落盘：不能依赖 mtime，zip 解压/git 检出都会重置时间。
# Gradle 打包前用同样的算法重算哈希比对，避免再出现「壳更新了、.so 还是旧的」。
VER="$(sed -n 's/.*to_jstring(\&mut env, "\([0-9.]*\)".*/\1/p' "$ROOT/core/src/lib.rs" | head -1)"
SRC_HASH="$(find "$ROOT/core/src" -type f -name '*.rs' -print | LC_ALL=C sort | xargs cat | sha256sum | cut -d' ' -f1)"
# Cargo 清单/锁定文件也纳入哈希，依赖或构建配置被改也必须重编。
CARGO_HASH="$(for f in .cargo/config.toml Cargo.lock Cargo.toml; do
  [ -f "$f" ] || continue
  printf '%s\n' "$f"
  cat "$f"
done | sha256sum | cut -d' ' -f1)"
# 两个 .so 的摘要一起落盘，防止二进制被误替换而源码没变。
SO_ARM64="$(sha256sum "$ROOT/app/src/main/jniLibs/arm64-v8a/libnanmen_core.so" | cut -d' ' -f1)"
SO_ARM32="$(sha256sum "$ROOT/app/src/main/jniLibs/armeabi-v7a/libnanmen_core.so" | cut -d' ' -f1)"
[ -n "$VER" ] && printf '%s\n%s\n%s\n%s\n%s\n' \
  "$VER" "$SRC_HASH" "$CARGO_HASH" "$SO_ARM64" "$SO_ARM32" > "$ROOT/app/src/main/jniLibs/kernel_version.txt"
echo "native libs updated: $VER"
