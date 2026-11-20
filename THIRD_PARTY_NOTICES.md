# 第三方组件声明

南门DNS 整体以 **GPL-3.0-only** 发布。源码树中包含以下第三方组件；它们仍按各自许可证分发。

## QuickJS

- 位置：`core/vendor/rquickjs-sys/quickjs/`
- 许可证：MIT
- 版权：Copyright (c) 2017-2026 Fabrice Bellard；Copyright (c) 2017-2024 Charlie Gordon；Copyright (c) 2023-2026 Ben Noordhuis
- 完整许可证：`core/vendor/rquickjs-sys/quickjs/LICENSE`

## rquickjs / rquickjs-sys

- 位置：`core/vendor/rquickjs-sys/`
- 版本：0.12.2
- 许可证：MIT
- 版权：Copyright (c) Mees Delzenne
- 来源：https://github.com/DelSkayn/rquickjs

MIT 许可证文本：

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Gradle Wrapper

- 位置：`gradle/wrapper/`、`gradlew`、`gradlew.bat`
- 许可证：Apache License 2.0
- 来源：https://github.com/gradle/gradle

## 其他依赖

`core/Cargo.lock` 中列出的其他 Rust crate 由 Cargo 在构建时获取，不随源码树直接分发；其许可证以各自 crate 元数据为准。AndroidX / Jetpack Compose 等 Android 依赖通过 Gradle 解析，同样不随源码树直接分发。
