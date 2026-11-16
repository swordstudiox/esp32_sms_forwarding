# ESP-IDF SDK patches

本目录保存必须在构建前严格应用到外部 ESP-IDF SDK 的补丁。`tools/apply_idf_patches.py` 会先检查所有适用补丁；补丁既不能正向应用、也不能识别为已应用时会立即失败，不做模糊或部分应用。

- `mbedtls/0001-x509-parse-all-certificate-policy-oids.patch`：适用于本机 ESP-IDF 5.5.4 和 CI 的 ESP-IDF 6.0.2，兼容 GSMA RSP 证书策略 OID。
- `esp-idf/0001-crt-bundle-cross-signed-memory-leak.patch`：只适用于包含 `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY` 的 ESP-IDF 6 SDK，修复交叉签名 CA 回调的内存泄漏。本机 ESP-IDF 5.x 不含该功能，脚本会明确跳过。

检查但不修改 SDK：

```powershell
python tools\apply_idf_patches.py --idf-path E:\Espressif\esp-idf-v5.5.4 --check-only
```
