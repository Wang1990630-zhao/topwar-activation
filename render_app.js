/**
 * Render 部署版 — 口袋奇兵激活码在线校验端点
 *
 * 与 cloudflare_worker.js 完全等价（验签逻辑、密钥、返回格式一致）
 * 改写点：把 Web Crypto API 换成 Node.js crypto 模块，HTTP 路由用 Express
 *
 * 部署：render.com → New Web Service → 关联本目录
 * 访问：https://你的服务名.onrender.com/verify
 */

const express = require('express');
const crypto = require('node:crypto');

const app = express();
app.use(express.json());

// ═══════════════════════════════════════════════════════════
// 🔑 密钥 — 必须和 keygen_v2.js 里的 SHARED_SECRET 完全一致
// ═══════════════════════════════════════════════════════════
const SHARED_SECRET = 'bb7a683c4e895580ff293d0a6cc3cda5244a3c63c4a88af2fa689d23fdbbf0f1';

// ═══════════════════════════════════════════════════════════
// 🚫 黑名单 — 泄露/倒卖的码，把它的 jti 填进来，立即作废
// ═══════════════════════════════════════════════════════════
const BLACKLIST = [
  // 示例：'e15095582bd4bc54',
];

// ─── CORS ───
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

// ─── base64url 解码（Node.js Buffer 等价于 atob）───
function base64urlDecode(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf-8');
}

// ─── HMAC-SHA256 验签（与 keygen_v2 完全一致）───
function signPayload(payload) {
  const uids = (payload.uids && payload.uids.length) ? payload.uids : (payload.uid ? [payload.uid] : []);
  const data = payload.exp + '|' + payload.iat + '|' + (payload.jti || '') + '|' + uids.join(',');
  const sig = crypto.createHmac('sha256', SHARED_SECRET).update(data, 'utf-8').digest('hex');
  return sig.slice(0, 16); // 只取前 16 hex（与 keygen 一致）
}

// ─── 健康检查 ───
app.get(['/', '/health'], (req, res) => {
  res.json({ ok: true, service: 'topwar-activation' });
});

// ─── CORS 预检 ───
app.options('*', (req, res) => {
  res.set(CORS_HEADERS);
  res.status(204).end();
});

// ─── 验证端点 ───
app.post('/verify', (req, res) => {
  try {
    const body = req.body || {};
    const uid = String(body.uid || '').trim();
    const code = String(body.code || '').trim();

    if (!uid || !code) {
      return res.json({ ok: false, error: '缺少 uid 或 code' });
    }

    // 1. 解码 + 验签
    let payload;
    try {
      payload = JSON.parse(base64urlDecode(code));
    } catch (e) {
      return res.json({ ok: false, error: '激活码格式无效' });
    }

    if (!payload.v || !payload.exp || !payload.iat || !payload.sig) {
      return res.json({ ok: false, error: '激活码缺少必要字段' });
    }
    if (payload.v !== 2) {
      return res.json({ ok: false, error: '不支持的版本' });
    }

    const expectedSig = signPayload(payload);
    if (payload.sig !== expectedSig) {
      return res.json({ ok: false, error: '签名校验失败：激活码无效或被篡改' });
    }

    // 2. 黑名单
    if (payload.jti && BLACKLIST.indexOf(payload.jti) >= 0) {
      return res.json({ ok: false, error: '此激活码已被吊销' });
    }

    // 3. 一码多号：当前账号必须在码绑定的 uid 列表里
    const uids = (payload.uids && payload.uids.length) ? payload.uids : (payload.uid ? [payload.uid] : []);
    if (uids.indexOf(uid) < 0) {
      return res.json({ ok: false, error: '此激活码未绑定当前账号' });
    }

    // 4. 过期检查（用服务器时间）
    const expireMs = new Date(payload.exp).getTime();
    if (isNaN(expireMs)) {
      return res.json({ ok: false, error: '到期时间解析失败' });
    }
    if (Date.now() >= expireMs) {
      return res.json({ ok: false, expired: true, error: '激活码已过期' });
    }

    return res.json({ ok: true, expireMs });
  } catch (e) {
    return res.json({ ok: false, error: '服务器错误：' + (e.message || String(e)) });
  }
});

// ─── 404 ───
app.use((req, res) => {
  res.json({ ok: false, error: 'not found' });
});

// ─── 启动 ───
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[topwar-activation] listening on :${PORT}`);
});
