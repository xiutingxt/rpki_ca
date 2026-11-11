# 本机源码开发检查（可选）

仅面向选择本机开发的贡献者，需要 Rust/Cargo、平台编译工具链；Python/OpenSSL 测试需要对应工具。普通 Docker 使用者无需安装这些环境，运行流程见 [Docker 使用指南](docker-workflows.md)。

修改代码后的基本检查：

```bash
cargo fmt --all --check
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- \
  -D warnings \
  -A clippy::result_large_err \
  -A clippy::collapsible_if
```

只检查实验流程可运行 `cargo test --offline experiment::tests`。独立验签检查可运行 `python3 tests/test_independent_verify.py`（用 `OPENSSL` 指定非默认 OpenSSL 路径）。

