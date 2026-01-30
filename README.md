# npm

需要设置的变量
```
配置优先级：命令行参数 > 环境变量 > 默认值
const CONFIG = {
  UUID: (argv.uuid || argv.u || process.env.UUID || 'feefeb96-bfcf-4a9b-aac0-6aac771c1b98').replace(/-/g, ""),
  PORT: argv.port || argv.p || process.env.PORT || 7860,
  K_S: argv.ks || process.env.K_S || '',
  C_B: argv.cb || process.env.C_B || 'www.shopify.com',
  K_K: argv.kk || process.env.K_K || '',
  C_T: argv.ct || process.env.C_T || '',
  C_D: argv.cd || argv.host || process.env.C_D || ''
};

```

运行：
```
npm install @jfux/kows
npx kows --port  --ks  --kk  --ct  --cd
```
