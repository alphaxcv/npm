# nzonesb

## 使用方式
```bash
npm install -g @jfux/nzonesb
nzonesb
```

## 环境变量
仅支持环境变量配置，未提供命令行参数：

- `PORT` HTTP 服务端口（默认 `3000`）
- `VLESS_PORT` VLESS-WS 端口（默认 `8002`）
- `VLESS_UUID` VLESS UUID（默认 `feefeb96-bfcf-4a9b-aac0-6aac771c1b98`）
- `VLESS_PATH` VLESS-WS 路径（默认 `/vls`）
- `HY2_PORT` Hysteria2 端口
- `HY2_PASSWORD` Hysteria2 密码
- `HY2_SNI` Hysteria2 SNI（默认 `www.bing.com`）
- `REALITY_PORT` Reality 端口
- `REALITY_SNI` Reality SNI（默认 `www.microsoft.com`）
- `REALITY_SHORT_ID` Reality short id（默认 `0123456789abcdef`）
- `REALITY_PRIVATE_KEY` / `REALITY_PUBLIC_KEY` Reality 密钥（可留空自动生成）
- `TUIC_PORT` TUIC 端口
- `TUIC_UUID` / `TUIC_PASSWORD` TUIC 账号信息
- `C_T` Cloudflared token（为空时尝试临时隧道）
- `C_D` Cloudflared 域名（自动生成或手动指定）
- `B_D` 伪装域名（默认 `www.shopify.com`）
- `N_S` / `N_P` / `N_K` Nezha 相关配置
- `NZ_UUID` Nezha UUID（可选）
- `N_T` Nezha 连接参数（默认 `--tls`）
- `TLS_CERT_PATH` / `TLS_KEY_PATH` 自定义证书路径（可选）

## 示例
```bash
set PORT=3000
set VLESS_PORT=8002
set VLESS_UUID=feefeb96-bfcf-4a9b-aac0-6aac771c1b98
nzonesb
```
