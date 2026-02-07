# nzonews

## 使用方式
```bash
npm install -g @jfux/nzonews
nzonews
```

## 环境变量
仅支持环境变量配置，未提供命令行参数：

  UUID: (process.env.UUID || '').replace(/-/g, ""),
  PORT: process.env.PORT || 3000,
  N_S: process.env.N_S || '',
  N_P: process.env.N_P || '443',
  N_K: process.env.N_K || '',
  NZ_UUID: process.env.NZ_UUID || '',
  N_T: process.env.N_T || '--tls',
  C_B: process.env.C_B || ',
  C_T: process.env.C_T || '',
  C_D: process.env.C_D || ''

## 示例
```bash
set PORT=3000
nzonews
```
