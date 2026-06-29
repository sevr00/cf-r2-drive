const DEFAULT_CONFIG = {
  MAX_SIZE_MB: 50000,
  CHUNK_SIZE: 5 * 1024 * 1024,
  SHARE_EXPIRE_DAYS: 7,
  MAX_QUOTA_BYTES: 100 * 1024 * 1024 * 1024
};
function getConfig(env) {
  return {
    maxSize: (env.MAX_SIZE_MB || DEFAULT_CONFIG.MAX_SIZE_MB) * 1024 * 1024,
    chunkSize: env.CHUNK_SIZE || DEFAULT_CONFIG.CHUNK_SIZE,
    shareExpireDays: env.SHARE_EXPIRE_DAYS || DEFAULT_CONFIG.SHARE_EXPIRE_DAYS,
    maxQuotaBytes: env.MAX_QUOTA_BYTES || DEFAULT_CONFIG.MAX_QUOTA_BYTES
  };
}

const ErrorCode = {
  UNAUTHORIZED:             { code: 'UNAUTHORIZED',             status: 401, message: '未授权' },
  INVALID_PATH:             { code: 'INVALID_PATH',             status: 400, message: '路径非法' },
  FILE_NOT_FOUND:           { code: 'FILE_NOT_FOUND',           status: 404, message: '文件不存在' },
  TARGET_EXISTS:            { code: 'TARGET_EXISTS',            status: 409, message: '目标已存在' },
  UPLOAD_SESSION_NOT_FOUND: { code: 'UPLOAD_SESSION_NOT_FOUND', status: 404, message: '上传会话不存在' },
  UPLOAD_INCOMPLETE:        { code: 'UPLOAD_INCOMPLETE',        status: 400, message: '分片上传不完整' },
  QUOTA_EXCEEDED:           { code: 'QUOTA_EXCEEDED',           status: 400, message: '存储空间不足' },
  FILE_TOO_LARGE:           { code: 'FILE_TOO_LARGE',           status: 413, message: '文件超出大小限制' },
  TIMEOUT_RISK:             { code: 'TIMEOUT_RISK',             status: 503, message: '请求超时' }
};

function errorResponse(err, status = 400) {
  return jsonResponse(
    { error: err.message || err, code: err.code || 'UNKNOWN' },
    { status: err.status || status }
  );
}

function jsonResponse(data, options = {}) {
  const { status = 200, extraHeaders = {} } = options;
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json;charset=UTF-8', ...extraHeaders }
  });
}

function getCorsHeaders(env) {
  const origin = env.ALLOWED_ORIGIN || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Range',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
    'Access-Control-Max-Age': '86400'
  };
}

function addCors(response, env) {
  const corsHeaders = getCorsHeaders(env);
  for (const [k, v] of Object.entries(corsHeaders)) {
    response.headers.set(k, v);
  }
  return response;
}

// ==================== 安全工具 ====================

/**
 * 修复：时序安全的字符串比较，防止时序攻击
 */
async function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  // 长度不同时仍然执行比较，避免通过响应时间推断长度
  if (aBytes.length !== bBytes.length) {
    // 执行一次无意义比较以保持时序一致
    await crypto.subtle.digest('SHA-256', aBytes);
    return false;
  }
  const aKey = await crypto.subtle.importKey('raw', aBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const bKey = await crypto.subtle.importKey('raw', bBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const testData = crypto.getRandomValues(new Uint8Array(32));
  const aSig = await crypto.subtle.sign('HMAC', aKey, testData);
  const bSig = await crypto.subtle.sign('HMAC', bKey, testData);
  return timingSafeEqual(new Uint8Array(aSig), new Uint8Array(bSig));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ==================== 路径与类型工具 ====================

/**
 * 修复：先解码再校验，防止 URL 编码绕过路径穿越检测
 */
function isValidPath(path) {
  if (path === null || path === undefined || typeof path !== 'string') return false;
  let decoded;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return false;
  }
  if (decoded.startsWith('/')) return false;
  if (decoded.includes('..') || decoded.includes('./') || decoded.includes('//')) return false;
  if (/[<>:"|?*\x00-\x1f\\]/.test(decoded)) return false;
  const parts = decoded.split('/');
  if (parts.some(p => p === '')) return false;
  return true;
}

function normalizeVirtualPath(path = '') {
  return String(path || '').replace(/\\/g, '/').trim()
    .replace(/^\/+/, '').replace(/\/+$/, '')
    .split('/').filter(Boolean).join('/');
}

function virtualPathName(path = '') {
  const parts = normalizeVirtualPath(path).split('/');
  return parts.pop() || '';
}

function virtualParentPath(path = '') {
  const parts = normalizeVirtualPath(path).split('/');
  parts.pop();
  return parts.join('/');
}

function getMimeType(filename) {
  const ext = String(filename || '').split('.').pop()?.toLowerCase();
  const map = {
    txt: 'text/plain', html: 'text/html', css: 'text/css',
    js: 'application/javascript', json: 'application/json',
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml',
    pdf: 'application/pdf', mp4: 'video/mp4', mp3: 'audio/mpeg',
    zip: 'application/zip', md: 'text/markdown', xml: 'application/xml',
    csv: 'text/csv'
  };
  return map[ext] || 'application/octet-stream';
}

function parseByteRange(rangeHeader, size) {
  if (!rangeHeader) return null;
  const match = String(rangeHeader).trim().match(/^bytes=(\d*)-(\d*)$/i);
  if (!match || (match[1] === '' && match[2] === '')) return { invalid: true };
  let start = match[1] === '' ? Math.max(size - Number(match[2]), 0) : Number(match[1]);
  let end   = match[2] === '' ? size - 1 : Number(match[2]);
  if (start >= size || end < start) return { invalid: true };
  end = Math.min(end, size - 1);
  return { start, end, length: end - start + 1 };
}

// ==================== SQL 构建辅助 ====================

/**
 * 修复：统一 parent_id 条件构建，彻底消除 SQL 拼接
 * 返回 { clause, params } 由调用方安全绑定
 */
function parentClause(parentId) {
  return parentId === null || parentId === undefined
    ? { clause: 'IS NULL', params: [] }
    : { clause: '= ?',    params: [parentId] };
}

// ==================== D1 关系型数据库操作 ====================

async function ensureD1Schema(DB) {


  await DB.batch([
    DB.prepare(`
      CREATE TABLE IF NOT EXISTS drive_nodes (
        id                 TEXT PRIMARY KEY,
        parent_id          TEXT,
        name               TEXT NOT NULL,
        is_folder          INTEGER NOT NULL,
        size               INTEGER DEFAULT 0,
        r2_key             TEXT,
        status             TEXT DEFAULT 'active',
        created_at         TEXT,
        updated_at         TEXT,
        client_modified_at TEXT
      )
    `),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_parent_status ON drive_nodes (parent_id, status)`),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_node_status   ON drive_nodes (status)`),
    DB.prepare(`
      CREATE TABLE IF NOT EXISTS drive_shares (
        token       TEXT PRIMARY KEY,
        node_id     TEXT NOT NULL,
        share_type  TEXT DEFAULT 'public',
        password    TEXT,
        expires_at  INTEGER,
        created_at  TEXT
      )
    `),
    DB.prepare(`
      CREATE TABLE IF NOT EXISTS drive_settings (
        key   TEXT PRIMARY KEY,
        value TEXT
      )
    `),
    DB.prepare(`
      CREATE TABLE IF NOT EXISTS drive_uploads (
        upload_id          TEXT PRIMARY KEY,
        node_id            TEXT NOT NULL,
        total_size         INTEGER,
        chunk_size         INTEGER,
        total_chunks       INTEGER,
        r2_key             TEXT,
        client_modified_at TEXT,
        created_at         TEXT
      )
    `),
    DB.prepare(`
      CREATE TABLE IF NOT EXISTS drive_upload_parts (
        upload_id   TEXT,
        chunk_index INTEGER,
        etag        TEXT,
        PRIMARY KEY (upload_id, chunk_index)
      )
    `),
    DB.prepare(`
      CREATE TABLE IF NOT EXISTS drive_clipboards (
        id         TEXT PRIMARY KEY,
        data       TEXT,
        expires_at INTEGER
      )
    `),
    DB.prepare(`
      CREATE TABLE IF NOT EXISTS drive_backup_dirs (
        client_id TEXT PRIMARY KEY,
        dirs      TEXT
      )
    `)
  ]);
}

// ==================== 配额管理 ====================

async function getQuota(DB) {
  const row = await DB.prepare(`SELECT value FROM drive_settings WHERE key = 'quota'`).first();
  return row ? parseInt(row.value, 10) : 0;
}

async function setQuota(DB, total) {
  await DB.prepare(`
    INSERT INTO drive_settings (key, value) VALUES ('quota', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).bind(String(Math.max(0, total))).run();
}

/**
 * 修复：使用原子 SQL 更新配额，避免并发竞争条件
 */
async function updateQuota(DB, delta) {
  await DB.prepare(`
    INSERT INTO drive_settings (key, value) VALUES ('quota', '0')
    ON CONFLICT(key) DO UPDATE SET
    value = CAST(MAX(0, CAST(value AS INTEGER) + ?) AS TEXT)
  `).bind(delta).run();
}

// ==================== 树形关系解析 ====================

async function resolvePathToNode(DB, path) {
  const cleanPath = normalizeVirtualPath(path);
  if (!cleanPath) return { id: null, parent_id: null, is_folder: 1 };

  const parts = cleanPath.split('/');
  let currentParentId = null;
  let currentNode = null;

  for (const part of parts) {
    const { clause, params } = parentClause(currentParentId);
    const stmt = DB.prepare(
      `SELECT * FROM drive_nodes WHERE name = ? AND status = 'active' AND parent_id ${clause}`
    ).bind(part, ...params);
    currentNode = await stmt.first();
    if (!currentNode) return null;
    currentParentId = currentNode.id;
  }
  return currentNode;
}

/**
 * 修复：使用 CTE 递归查询替代 N+1 循环查询
 */
async function getFullVirtualPath(DB, nodeId) {
  if (!nodeId) return '';
  try {
    const result = await DB.prepare(`
      WITH RECURSIVE path_cte AS (
        SELECT id, parent_id, name, 0 AS depth
        FROM drive_nodes
        WHERE id = ?
        UNION ALL
        SELECT n.id, n.parent_id, n.name, p.depth + 1
        FROM drive_nodes n
        JOIN path_cte p ON n.id = p.parent_id
      )
      SELECT name FROM path_cte ORDER BY depth DESC
    `).bind(nodeId).all();
    return (result.results || []).map(r => r.name).join('/');
  } catch {
    // D1 不支持 CTE 时降级为迭代查询
    let currentId = nodeId;
    const pathParts = [];
    let safety = 0;
    while (currentId && safety++ < 50) {
      const node = await DB.prepare(
        `SELECT id, parent_id, name FROM drive_nodes WHERE id = ?`
      ).bind(currentId).first();
      if (!node) break;
      pathParts.unshift(node.name);
      currentId = node.parent_id;
    }
    return pathParts.join('/');
  }
}

/**
 * 修复：parentId 改用参数绑定
 */
async function ensureFoldersByPath(DB, path) {
  const cleanPath = normalizeVirtualPath(path);
  if (!cleanPath) return null;

  const parts = cleanPath.split('/');
  let currentParentId = null;

  for (const part of parts) {
    const { clause, params } = parentClause(currentParentId);
    const existing = await DB.prepare(
      `SELECT id FROM drive_nodes
       WHERE name = ? AND is_folder = 1 AND status = 'active' AND parent_id ${clause}`
    ).bind(part, ...params).first();

    if (existing) {
      currentParentId = existing.id;
    } else {
      const newId = crypto.randomUUID();
      const now = new Date().toISOString();
      await DB.prepare(`
        INSERT INTO drive_nodes (id, parent_id, name, is_folder, size, status, created_at, updated_at)
        VALUES (?, ?, ?, 1, 0, 'active', ?, ?)
      `).bind(newId, currentParentId, part, now, now).run();
      currentParentId = newId;
    }
  }
  return currentParentId;
}

/**
 * 修复：parentId 改用参数绑定
 */
async function getUniqueName(DB, parentId, name, isFolder) {
  let counter = 1;
  let currentName = name;
  while (true) {
    const { clause, params } = parentClause(parentId);
    const stmt = DB.prepare(
      `SELECT id FROM drive_nodes
       WHERE name = ? AND status = 'active' AND parent_id ${clause}`
    ).bind(currentName, ...params);
    if (!(await stmt.first())) break;

    if (isFolder) {
      currentName = `${name}(${counter})`;
    } else {
      const dotIndex = name.lastIndexOf('.');
      const base = dotIndex > 0 ? name.substring(0, dotIndex) : name;
      const ext  = dotIndex > 0 ? name.substring(dotIndex) : '';
      currentName = `${base}(${counter})${ext}`;
    }
    counter++;
  }
  return currentName;
}

// ==================== 递归操作（迭代 BFS 实现，防止栈溢出） ====================

/**
 * 修复：改用 BFS 迭代替代递归，添加深度/数量上限保护
 */
async function bfsUpdateStatus(DB, rootNodeId, newStatus) {
  const queue = [rootNodeId];
  const now = new Date().toISOString();
  let processed = 0;
  const MAX_NODES = 50000;

  while (queue.length > 0 && processed < MAX_NODES) {
    const batchIds = queue.splice(0, 100);
    processed += batchIds.length;

    const placeholders = batchIds.map(() => '?').join(',');
    await DB.prepare(
      `UPDATE drive_nodes SET status = ?, updated_at = ? WHERE parent_id IN (${placeholders})`
    ).bind(newStatus, now, ...batchIds).run();

    const children = await DB.prepare(
      `SELECT id FROM drive_nodes WHERE parent_id IN (${placeholders}) AND is_folder = 1`
    ).bind(...batchIds).all();

    for (const child of children.results || []) {
      queue.push(child.id);
    }
  }
}

/**
 * 修复：BFS 迭代删除，同时正确清理分享记录
 */
async function bfsDeleteNodes(DB, rootNodeId, R2) {
  const allIds = [];
  const queue = [rootNodeId];
  let safety = 0;
  const MAX_NODES = 50000;

  while (queue.length > 0 && safety++ < MAX_NODES) {
    const batchIds = queue.splice(0, 100);
    allIds.push(...batchIds);
    const placeholders = batchIds.map(() => '?').join(',');
    const children = await DB.prepare(
      `SELECT id FROM drive_nodes WHERE parent_id IN (${placeholders})`
    ).bind(...batchIds).all();
    for (const child of children.results || []) queue.push(child.id);
  }

  let totalFreed = 0;
  const BATCH = 100;
  for (let i = 0; i < allIds.length; i += BATCH) {
    const batch = allIds.slice(i, i + BATCH);
    const placeholders = batch.map(() => '?').join(',');
    const fileNodes = await DB.prepare(
      `SELECT r2_key, size FROM drive_nodes
       WHERE id IN (${placeholders}) AND is_folder = 0 AND r2_key IS NOT NULL`
    ).bind(...batch).all();

    for (const node of fileNodes.results || []) {
      try { await R2.delete(node.r2_key); } catch {}
      totalFreed += node.size || 0;
    }

    await DB.prepare(
      `DELETE FROM drive_nodes WHERE id IN (${placeholders})`
    ).bind(...batch).run();
    await DB.prepare(
      `DELETE FROM drive_shares WHERE node_id IN (${placeholders})`
    ).bind(...batch).run();
  }
  return totalFreed;
}

/**
 * 修复：BFS 迭代复制，替代递归实现
 */
async function bfsCopyNode(DB, R2, sourceNode, targetParentId, targetName) {
  const finalName = targetName || sourceNode.name;
  const now = new Date().toISOString();
  let totalCopied = 0;

  // 队列元素：{ srcNode, destParentId, destName }
  const queue = [{ srcNode: sourceNode, destParentId: targetParentId, destName: finalName }];
  let safety = 0;
  const MAX_NODES = 10000;

  while (queue.length > 0 && safety++ < MAX_NODES) {
    const { srcNode, destParentId, destName } = queue.shift();
    const newId = crypto.randomUUID();

    if (srcNode.is_folder === 0) {
      if (!srcNode.r2_key) continue;
      const obj = await R2.get(srcNode.r2_key);
      if (!obj) continue;
      const newR2Key = crypto.randomUUID();
      await R2.put(newR2Key, obj.body, { httpMetadata: obj.httpMetadata });
      await DB.prepare(`
        INSERT INTO drive_nodes (id, parent_id, name, is_folder, size, r2_key, status, created_at, updated_at)
        VALUES (?, ?, ?, 0, ?, ?, 'active', ?, ?)
      `).bind(newId, destParentId, destName, srcNode.size || 0, newR2Key, now, now).run();
      totalCopied += srcNode.size || 0;
    } else {
      await DB.prepare(`
        INSERT INTO drive_nodes (id, parent_id, name, is_folder, size, status, created_at, updated_at)
        VALUES (?, ?, ?, 1, 0, 'active', ?, ?)
      `).bind(newId, destParentId, destName, now, now).run();

      const children = await DB.prepare(
        `SELECT * FROM drive_nodes WHERE parent_id = ? AND status = 'active'`
      ).bind(srcNode.id).all();

      for (const child of children.results || []) {
        queue.push({ srcNode: child, destParentId: newId, destName: child.name });
      }
    }
  }
  return totalCopied;
}

/**
 * 修复：恢复父链时正确处理自身节点，使用 nodeId 直接操作
 */
async function restoreParentChain(DB, nodeId) {
  let currentId = nodeId;
  let safety = 0;
  while (currentId && safety++ < 100) {
    const node = await DB.prepare(
      `SELECT id, parent_id, status FROM drive_nodes WHERE id = ?`
    ).bind(currentId).first();
    if (!node) break;
    if (node.status !== 'active') {
      await DB.prepare(
        `UPDATE drive_nodes SET status = 'active', updated_at = ? WHERE id = ?`
      ).bind(new Date().toISOString(), node.id).run();
    }
    currentId = node.parent_id;
  }
}

/**
 * 修复：递归计算文件夹真实大小（用于 copy 配额预检）
 */
async function calcFolderSize(DB, nodeId) {
  let total = 0;
  const queue = [nodeId];
  let safety = 0;
  while (queue.length > 0 && safety++ < 50000) {
    const batchIds = queue.splice(0, 100);
    const placeholders = batchIds.map(() => '?').join(',');

    const files = await DB.prepare(
      `SELECT size FROM drive_nodes
       WHERE parent_id IN (${placeholders}) AND is_folder = 0 AND status = 'active'`
    ).bind(...batchIds).all();
    for (const f of files.results || []) total += f.size || 0;

    const folders = await DB.prepare(
      `SELECT id FROM drive_nodes
       WHERE parent_id IN (${placeholders}) AND is_folder = 1 AND status = 'active'`
    ).bind(...batchIds).all();
    for (const f of folders.results || []) queue.push(f.id);
  }
  return total;
}

// ==================== 静态文件呈现 ====================

async function serveStaticFromR2(R2, key, fallback = '') {
  try {
    const object = await R2.get(key);
    if (object) return await object.text();
  } catch (e) {
    console.warn('Failed to read static file:', key, e);
  }
  return fallback;
}

function getDefaultPage(siteTitle) {
  const escaped = String(siteTitle).replace(/[<>&"]/g, c =>
    ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c])
  );
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${escaped}</title>
<style>body{font-family:sans-serif;max-width:600px;margin:4rem auto;text-align:center;color:#1e293b}</style>
</head><body><h1>📁 ${escaped}</h1><p>企业级强一致性架构部署成功，请上传前端静态文件。</p></body></html>`;
}

// ==================== Shared 渲染 ====================

function renderSharedPage(folders, files, currentPath, siteTitle) {
  const sharedBase = '/shared';
  const pathParts = currentPath ? currentPath.split('/').filter(Boolean) : [];

  const escHtml = s => String(s).replace(/[<>&"]/g, c =>
    ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c])
  );

  let breadcrumbHtml = `<a href="${sharedBase}" class="text-blue-600 hover:underline">共享文件夹</a>`;
  pathParts.forEach((p, i) => {
    const href = `${sharedBase}/?path=${encodeURIComponent(pathParts.slice(0, i + 1).join('/'))}`;
    breadcrumbHtml += ` <span class="mx-1">/</span> `;
    breadcrumbHtml += (i === pathParts.length - 1)
      ? `<span class="font-medium">${escHtml(p)}</span>`
      : `<a href="${href}" class="text-blue-600 hover:underline">${escHtml(p)}</a>`;
  });

  let listHtml = '';
  if (folders.length === 0 && files.length === 0) {
    listHtml = `<p class="text-gray-500 text-center py-8">此文件夹为空</p>`;
  } else {
    const items = [
      ...folders.map(f => ({ name: f, isFolder: true })),
      ...files.map(f => ({ name: f.name, size: f.size, isFolder: false }))
    ];
    listHtml = `<ul class="divide-y divide-gray-200">${items.map(item => {
      const subPath = currentPath ? `${currentPath}/${item.name}` : item.name;
      return `
        <li class="py-3 flex items-center gap-3">
          <span class="text-2xl">${item.isFolder ? '📁' : '📄'}</span>
          <span class="flex-1">
            ${item.isFolder
              ? `<a href="${sharedBase}/?path=${encodeURIComponent(subPath)}" class="text-blue-600 hover:underline font-medium">${escHtml(item.name)}</a>`
              : escHtml(item.name)}
          </span>
          ${!item.isFolder
            ? `<a href="/api/download?path=${encodeURIComponent('shared/' + subPath)}" class="text-blue-600 hover:underline text-sm">下载</a>`
            : ''}
        </li>`;
    }).join('')}</ul>`;
  }

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${escHtml(siteTitle)} - 共享</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:2rem;background:#f8fafc;color:#1e293b}.content{background:#fff;border-radius:8px;padding:1.5rem;border:1px solid #e2e8f0;margin-top:1.5rem;}</style>
</head><body>
<header><h1>📂 ${escHtml(siteTitle)}</h1><div style="margin-top:1rem">${breadcrumbHtml}</div></header>
<div class="content">${listHtml}</div>
</body></html>`;
}

// ==================== API 路由分发 ====================
let schemaInitialized = false;
export default {
  async fetch(request, env, ctx) { 
    const url      = new URL(request.url);
    const pathname = url.pathname;
    const method   = request.method;

    if (!env.ADMIN_TOKEN || !env.BUCKET || !env.DB) {
      return errorResponse({ message: 'Missing Configurations', code: 'CONFIG_ERR' }, 500);
    }

    const DB        = env.DB;
    const R2        = env.BUCKET;
    // 修复：正确的schema初始化缓存
    if (!schemaInitialized) {
        await ensureD1Schema(DB);
        schemaInitialized = true;
    }
    const siteTitle = env.SITE_TITLE || 'R2 云盘';

    // 每次请求均保证表结构存在（IF NOT EXISTS 保证幂等性）

    if (method === 'OPTIONS') {
      return new Response(null, { headers: getCorsHeaders(env) });
    }

    // ---- 鉴权 ----
    const publicPrefixes = ['/api/login', '/api/config', '/api/shared-list', '/share/', '/shared'];
    const isPublicPath = publicPrefixes.some(p => pathname.startsWith(p))
      || pathname === '/' || pathname === '';

    let needToken = !isPublicPath;
    if (pathname === '/api/backup-dirs' && method === 'GET') needToken = false;
    if (pathname === '/api/clipboard') needToken = true;
    if (
      (pathname === '/api/file' || pathname === '/api/download')
      && url.searchParams.get('path')?.startsWith('shared/')
    ) needToken = false;

    if (needToken) {
      const token = url.searchParams.get('token')
        || request.headers.get('Authorization')?.replace('Bearer ', '');
      // 修复：使用时序安全比较
      if (!(await safeCompare(token || '', env.ADMIN_TOKEN))) {
        return addCors(errorResponse(ErrorCode.UNAUTHORIZED, 401), env);
      }
    }

    const config = getConfig(env);
    try {

      // ================================================================
      // 登录 & 配置
      // ================================================================

      if (method === 'POST' && pathname === '/api/login') {
        const body = await request.json().catch(() => ({}));
        const ok = await safeCompare(body.token || '', env.ADMIN_TOKEN);
        return addCors(
          ok ? jsonResponse({ success: true }) : errorResponse(ErrorCode.UNAUTHORIZED, 401),
          env
        );
      }

      if (method === 'GET' && pathname === '/api/config') {
        return addCors(
          jsonResponse({ maxQuotaBytes: config.maxQuotaBytes, chunkSize: config.chunkSize, siteTitle }),
          env
        );
      }

      if (method === 'GET' && pathname === '/api/quota') {
        return addCors(
          jsonResponse({ used: await getQuota(DB), max: config.maxQuotaBytes }),
          env
        );
      }
if (method === 'GET' && pathname === '/api/search') {
  const q = url.searchParams.get('q') || '';
  if (q.length < 2) return addCors(jsonResponse({ files: [] }), env);
  
  const results = await DB.prepare(
    `SELECT id, parent_id, name, size, created_at as uploaded, r2_key
     FROM drive_nodes 
     WHERE status = 'active' AND is_folder = 0 AND name LIKE ?
     LIMIT 100`
  ).bind(`%${q}%`).all();
  
  const files = await Promise.all((results.results || []).map(async row => ({
    name: row.name,
    path: await getFullVirtualPath(DB, row.id),
    size: row.size,
    uploaded: row.uploaded
  })));
  
  return addCors(jsonResponse({ files }), env);
}
      // ================================================================
      // 目录列表
      // ================================================================

      if (method === 'GET' && pathname === '/api/dir') {
        const path       = normalizeVirtualPath(url.searchParams.get('path'));
        const targetNode = await resolvePathToNode(DB, path);
        if (path && !targetNode) return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);

        const effectiveId = targetNode?.id ?? null;
        const { clause, params } = parentClause(effectiveId);
        const children = await DB.prepare(
          `SELECT name, is_folder, size, created_at, updated_at
           FROM drive_nodes WHERE status = 'active' AND parent_id ${clause}`
        ).bind(...params).all();

        const folders = [], files = [];
        for (const row of children.results || []) {
          if (row.is_folder === 1) folders.push(row.name);
          else files.push({ name: row.name, size: row.size, uploaded: row.created_at, updated: row.updated_at });
        }
        return addCors(jsonResponse({ folders, files, currentPath: path }), env);
      }

      // ================================================================
      // 文件树
      // ================================================================

      if (method === 'GET' && pathname === '/api/tree') {
        const allActive = await DB.prepare(
          `SELECT id, parent_id, name, is_folder, size, created_at
           FROM drive_nodes WHERE status = 'active'`
        ).all();

        const map  = {};
        const root = {};
        (allActive.results || []).forEach(row => {
          map[row.id] = {
            name: row.name, isFolder: row.is_folder === 1,
            children: {}, size: row.size || 0,
            uploaded: row.created_at, parentId: row.parent_id
          };
        });

        Object.keys(map).forEach(id => {
          const node = map[id];
          if (node.parentId && map[node.parentId]) {
            map[node.parentId].children[node.name] = node;
          } else {
            root[node.name] = node;
          }
        });

        function computeSizes(nodes) {
          let total = 0;
          for (const k in nodes) {
            if (nodes[k].isFolder) {
              nodes[k].size = computeSizes(nodes[k].children);
              total += nodes[k].size;
            } else {
              total += nodes[k].size || 0;
            }
          }
          return total;
        }
        computeSizes(root);
        return addCors(jsonResponse(root), env);
      }

      // ================================================================
      // 上传初始化
      // ================================================================

      if (method === 'POST' && pathname === '/api/upload/init') {
        const body = await request.json().catch(() => ({}));
        const { path: filePath, totalSize, overwrite, clientModifiedAt } = body;

        if (!isValidPath(filePath)) {
          return addCors(errorResponse(ErrorCode.INVALID_PATH, 400), env);
        }
        // 修复：校验 maxSize 限制
        if (totalSize > config.maxSize) {
          return addCors(errorResponse(ErrorCode.FILE_TOO_LARGE, 413), env);
        }
        // 配额预检
        const currentUsed = await getQuota(DB);
        if (currentUsed + totalSize > config.maxQuotaBytes) {
          return addCors(errorResponse(ErrorCode.QUOTA_EXCEEDED, 400), env);
        }

        const parentPath = virtualParentPath(filePath);
        const fileName   = virtualPathName(filePath);
        const parentId   = await ensureFoldersByPath(DB, parentPath);

        let finalName = fileName;

        if (overwrite) {
          // 修复：parentId 使用参数绑定
          const { clause, params } = parentClause(parentId);
          const exist = await DB.prepare(
            `SELECT id, r2_key, size FROM drive_nodes
             WHERE name = ? AND parent_id ${clause} AND is_folder = 0 AND status = 'active'`
          ).bind(fileName, ...params).first();

          if (exist) {
            await R2.delete(exist.r2_key);
            await updateQuota(DB, -(exist.size || 0));
            await DB.prepare(`DELETE FROM drive_nodes WHERE id = ?`).bind(exist.id).run();
          }
        } else {
          finalName = await getUniqueName(DB, parentId, fileName, false);
        }

        const r2Key = crypto.randomUUID();
        const now   = new Date().toISOString();

        // 空文件快速路径
        if (totalSize === 0) {
          await R2.put(r2Key, new ArrayBuffer(0));
          const nodeId = crypto.randomUUID();
          await DB.prepare(`
            INSERT INTO drive_nodes
              (id, parent_id, name, is_folder, size, r2_key, status, created_at, updated_at, client_modified_at)
            VALUES (?, ?, ?, 0, 0, ?, 'active', ?, ?, ?)
          `).bind(nodeId, parentId, finalName, r2Key, now, now, clientModifiedAt || null).run();
          return addCors(jsonResponse({
            uploadId: null, done: true, totalChunks: 0,
            path: parentPath ? `${parentPath}/${finalName}` : finalName
          }), env);
        }

        const multipart   = await R2.createMultipartUpload(r2Key);
        const uploadId    = multipart.uploadId;
        const totalChunks = Math.ceil(totalSize / config.chunkSize);
        const nodeId      = crypto.randomUUID();

        // 修复：使用 batch 保证原子性
        await DB.batch([
          DB.prepare(`
            INSERT INTO drive_nodes
              (id, parent_id, name, is_folder, size, r2_key, status, created_at, updated_at, client_modified_at)
            VALUES (?, ?, ?, 0, ?, ?, 'pending', ?, ?, ?)
          `).bind(nodeId, parentId, finalName, totalSize, r2Key, now, now, clientModifiedAt || null),
          DB.prepare(`
            INSERT INTO drive_uploads
              (upload_id, node_id, total_size, chunk_size, total_chunks, r2_key, created_at, client_modified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(uploadId, nodeId, totalSize, config.chunkSize, totalChunks, r2Key, now, clientModifiedAt || null)
        ]);

        return addCors(jsonResponse({
          uploadId, chunkSize: config.chunkSize, totalChunks,
          path: parentPath ? `${parentPath}/${finalName}` : finalName
        }), env);
      }

      // ================================================================
      // 分片上传
      // ================================================================

      if (method === 'PUT' && pathname === '/api/upload/chunk') {
        const uploadId   = url.searchParams.get('uploadId');
        const chunkIndex = parseInt(url.searchParams.get('chunkIndex'), 10);

        const uploadData = await DB.prepare(
          `SELECT r2_key, total_chunks FROM drive_uploads WHERE upload_id = ?`
        ).bind(uploadId).first();

        if (!uploadData || isNaN(chunkIndex) || chunkIndex < 0 || chunkIndex >= uploadData.total_chunks) {
          return addCors(errorResponse(ErrorCode.UPLOAD_SESSION_NOT_FOUND, 404), env);
        }

        const buffer          = await request.arrayBuffer();
        const multipartUpload = R2.resumeMultipartUpload(uploadData.r2_key, uploadId);
        const part            = await multipartUpload.uploadPart(chunkIndex + 1, buffer);

        await DB.prepare(
          `INSERT OR REPLACE INTO drive_upload_parts (upload_id, chunk_index, etag) VALUES (?, ?, ?)`
        ).bind(uploadId, chunkIndex, part.etag).run();

        return addCors(jsonResponse({ success: true, etag: part.etag }), env);
      }

      // ================================================================
      // 断点续传检查
      // ================================================================

      if (method === 'POST' && pathname === '/api/upload/check') {
        const body = await request.json().catch(() => ({}));
        const uploadData = await DB.prepare(
          `SELECT total_chunks FROM drive_uploads WHERE upload_id = ?`
        ).bind(body.uploadId).first();

        if (!uploadData) return addCors(jsonResponse({ exists: false }), env);

        const parts = await DB.prepare(
          `SELECT chunk_index FROM drive_upload_parts WHERE upload_id = ?`
        ).bind(body.uploadId).all();

        return addCors(jsonResponse({
          exists: true,
          uploadedChunks: (parts.results || []).map(p => p.chunk_index),
          totalChunks: uploadData.total_chunks
        }), env);
      }

      // ================================================================
      // 上传完成
      // ================================================================

      if (method === 'POST' && pathname === '/api/upload/complete') {
        const body = await request.json().catch(() => ({}));
        const uploadData = await DB.prepare(
          `SELECT * FROM drive_uploads WHERE upload_id = ?`
        ).bind(body.uploadId).first();

        if (!uploadData) return addCors(errorResponse(ErrorCode.UPLOAD_SESSION_NOT_FOUND, 404), env);

        const partsData = await DB.prepare(
          `SELECT chunk_index + 1 AS partNumber, etag
           FROM drive_upload_parts WHERE upload_id = ? ORDER BY chunk_index ASC`
        ).bind(body.uploadId).all();

        if ((partsData.results || []).length !== uploadData.total_chunks) {
          return addCors(errorResponse(ErrorCode.UPLOAD_INCOMPLETE, 400), env);
        }

        const multipartUpload = R2.resumeMultipartUpload(uploadData.r2_key, body.uploadId);
        await multipartUpload.complete(partsData.results);

        // 修复：使用 batch 原子更新，避免状态不一致
        const now = new Date().toISOString();
        await DB.batch([
          DB.prepare(
            `UPDATE drive_nodes SET status = 'active', updated_at = ? WHERE id = ?`
          ).bind(now, uploadData.node_id),
          // 正确做法：单独在batch外调用，或改用一致的SQL
          DB.prepare(
              `INSERT INTO drive_settings (key, value) VALUES ('quota', '0')
              ON CONFLICT(key) DO UPDATE SET
              value = CAST(MAX(0, CAST(value AS INTEGER) + ?) AS TEXT)`
          ).bind(uploadData.total_size),
          DB.prepare(
            `DELETE FROM drive_uploads WHERE upload_id = ?`
          ).bind(body.uploadId),
          DB.prepare(
            `DELETE FROM drive_upload_parts WHERE upload_id = ?`
          ).bind(body.uploadId)
        ]);

        const fullPath = await getFullVirtualPath(DB, uploadData.node_id);
        return addCors(jsonResponse({ success: true, path: fullPath }), env);
      }

      // ================================================================
      // 文件与目录操作
      // ================================================================

      if (method === 'POST' && pathname === '/api/op') {
        const body = await request.json().catch(() => ({}));
        const { op, srcPath, destPath, newName } = body;

        if (!isValidPath(srcPath)) {
          return addCors(errorResponse(ErrorCode.INVALID_PATH, 400), env);
        }

        // ---- mkdir ----
        if (op === 'mkdir') {
          const parentId = await ensureFoldersByPath(DB, virtualParentPath(srcPath));
          const name     = virtualPathName(srcPath);
          const { clause, params } = parentClause(parentId);
          const exist = await DB.prepare(
            `SELECT id FROM drive_nodes
             WHERE name = ? AND is_folder = 1 AND status = 'active' AND parent_id ${clause}`
          ).bind(name, ...params).first();
          if (exist) return addCors(errorResponse({ ...ErrorCode.TARGET_EXISTS, message: '目标文件夹已存在' }, 409), env);

          const newId = crypto.randomUUID();
          const now   = new Date().toISOString();
          await DB.prepare(`
            INSERT INTO drive_nodes (id, parent_id, name, is_folder, size, status, created_at, updated_at)
            VALUES (?, ?, ?, 1, 0, 'active', ?, ?)
          `).bind(newId, parentId, name, now, now).run();
          return addCors(jsonResponse({ success: true }), env);
        }

        // ---- createfile ----
        if (op === 'createfile') {
          const parentId = await ensureFoldersByPath(DB, virtualParentPath(srcPath));
          const name     = virtualPathName(srcPath);
          const { clause, params } = parentClause(parentId);
          const exist = await DB.prepare(
            `SELECT id FROM drive_nodes
             WHERE name = ? AND is_folder = 0 AND status = 'active' AND parent_id ${clause}`
          ).bind(name, ...params).first();
          if (exist) return addCors(errorResponse({ ...ErrorCode.TARGET_EXISTS, message: '目标文件已存在' }, 409), env);

          const r2Key = crypto.randomUUID();
          await R2.put(r2Key, new ArrayBuffer(0));
          const newId = crypto.randomUUID();
          const now   = new Date().toISOString();
          await DB.prepare(`
            INSERT INTO drive_nodes (id, parent_id, name, is_folder, size, r2_key, status, created_at, updated_at)
            VALUES (?, ?, ?, 0, 0, ?, 'active', ?, ?)
          `).bind(newId, parentId, name, r2Key, now, now).run();
          return addCors(jsonResponse({ success: true }), env);
        }

        // 以下操作需要源节点存在
        const srcNode = await resolvePathToNode(DB, srcPath);
        if (!srcNode) return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);

        // ---- rename ----
        if (op === 'rename') {
          if (!isValidPath(newName)) return addCors(errorResponse(ErrorCode.INVALID_PATH, 400), env);
          const { clause, params } = parentClause(srcNode.parent_id);
          const exist = await DB.prepare(
            `SELECT id FROM drive_nodes
             WHERE name = ? AND status = 'active' AND parent_id ${clause}`
          ).bind(newName, ...params).first();
          if (exist) return addCors(errorResponse({ ...ErrorCode.TARGET_EXISTS, message: '目标名称已存在' }, 409), env);
          await DB.prepare(
            `UPDATE drive_nodes SET name = ?, updated_at = ? WHERE id = ?`
          ).bind(newName, new Date().toISOString(), srcNode.id).run();
          return addCors(jsonResponse({ success: true }), env);
        }

        // ---- move ----
        if (op === 'move') {
          const destParentId = await ensureFoldersByPath(DB, destPath || '');
          const finalName    = await getUniqueName(DB, destParentId, srcNode.name, srcNode.is_folder === 1);
          await DB.prepare(
            `UPDATE drive_nodes SET parent_id = ?, name = ?, updated_at = ? WHERE id = ?`
          ).bind(destParentId, finalName, new Date().toISOString(), srcNode.id).run();
          return addCors(jsonResponse({ success: true }), env);
        }

        // ---- copy ----
        if (op === 'copy') {
          // 修复：正确计算文件夹真实大小
          const realSize = srcNode.is_folder === 1
            ? await calcFolderSize(DB, srcNode.id)
            : srcNode.size || 0;

          const currentQuota = await getQuota(DB);
          if (currentQuota + realSize > config.maxQuotaBytes) {
            return addCors(errorResponse(ErrorCode.QUOTA_EXCEEDED, 400), env);
          }

          const destParentId = await ensureFoldersByPath(DB, destPath || '');
          const finalName    = await getUniqueName(DB, destParentId, srcNode.name, srcNode.is_folder === 1);
          const copiedSize   = await bfsCopyNode(DB, R2, srcNode, destParentId, finalName);
          await updateQuota(DB, copiedSize);
          return addCors(jsonResponse({ success: true }), env);
        }

        // ---- delete（移入回收站） ----
        if (op === 'delete') {
          const now = new Date().toISOString();
          await DB.prepare(
            `UPDATE drive_nodes SET status = 'trashed', updated_at = ? WHERE id = ?`
          ).bind(now, srcNode.id).run();
          await DB.prepare(`DELETE FROM drive_shares WHERE node_id = ?`).bind(srcNode.id).run();

          if (srcNode.is_folder === 1) {
            // 修复：只更新当前文件夹的子节点，不影响其他 trashed 节点
            await bfsUpdateStatus(DB, srcNode.id, 'trashed');
          }
          return addCors(jsonResponse({ success: true }), env);
        }
      }

      // ================================================================
      // 回收站管理
      // ================================================================

      if (method === 'GET' && pathname === '/api/trash') {
        const trashed = await DB.prepare(
          `SELECT * FROM drive_nodes WHERE status = 'trashed' ORDER BY updated_at DESC`
        ).all();
        const results = await Promise.all((trashed.results || []).map(async row => ({
          id:         row.id,
          path:       await getFullVirtualPath(DB, row.id),
          is_folder:  row.is_folder === 1,
          size:       row.size,
          deleted_at: new Date(row.updated_at).getTime()
        })));
        return addCors(jsonResponse(results), env);
      }

      // 修复：改用 nodeId 精确恢复，避免同名文件误恢复
      if (method === 'POST' && pathname === '/api/restore') {
        const body = await request.json().catch(() => ({}));
        const nodeId = body.nodeId;
        if (!nodeId) return addCors(errorResponse({ message: 'nodeId 必填', code: 'MISSING_PARAM' }, 400), env);

        const trashedNode = await DB.prepare(
          `SELECT * FROM drive_nodes WHERE id = ? AND status = 'trashed'`
        ).bind(nodeId).first();
        if (!trashedNode) return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);

        // 修复：先恢复自身，再恢复父链，最后恢复子节点
        await DB.prepare(
          `UPDATE drive_nodes SET status = 'active', updated_at = ? WHERE id = ?`
        ).bind(new Date().toISOString(), trashedNode.id).run();

        await restoreParentChain(DB, trashedNode.parent_id);

        if (trashedNode.is_folder === 1) {
          await bfsUpdateStatus(DB, trashedNode.id, 'active');
        }
        return addCors(jsonResponse({ success: true }), env);
      }

      // 修复：改用 nodeId 精确永久删除
      if (method === 'DELETE' && pathname === '/api/permanent-delete') {
        const body = await request.json().catch(() => ({}));
        const nodeId = body.nodeId;
        if (!nodeId) return addCors(errorResponse({ message: 'nodeId 必填', code: 'MISSING_PARAM' }, 400), env);

        const trashedNode = await DB.prepare(
          `SELECT * FROM drive_nodes WHERE id = ? AND status = 'trashed'`
        ).bind(nodeId).first();
        if (!trashedNode) return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);

        let totalFreed = 0;
        if (trashedNode.is_folder === 0 && trashedNode.r2_key) {
          try { await R2.delete(trashedNode.r2_key); } catch {}
          totalFreed += trashedNode.size || 0;
        }
        if (trashedNode.is_folder === 1) {
          totalFreed += await bfsDeleteNodes(DB, trashedNode.id, R2);
        }

        await DB.batch([
          DB.prepare(`DELETE FROM drive_nodes WHERE id = ?`).bind(trashedNode.id),
          DB.prepare(`DELETE FROM drive_shares WHERE node_id = ?`).bind(trashedNode.id)
        ]);

        if (totalFreed > 0) await updateQuota(DB, -totalFreed);
        return addCors(jsonResponse({ success: true, freedBytes: totalFreed }), env);
      }

      // 修复：只处理真正的顶层 trashed 节点，避免重复删除子节点
      if (method === 'POST' && pathname === '/api/trash/clear') {
        const topLevelTrashed = await DB.prepare(`
          SELECT n.* FROM drive_nodes n
          WHERE n.status = 'trashed'
            AND (
              n.parent_id IS NULL
              OR NOT EXISTS (
                SELECT 1 FROM drive_nodes p
                WHERE p.id = n.parent_id AND p.status = 'trashed'
              )
            )
        `).all();

        let totalFreed = 0;
        for (const row of topLevelTrashed.results || []) {
          if (row.is_folder === 0 && row.r2_key) {
            try { await R2.delete(row.r2_key); } catch {}
            totalFreed += row.size || 0;
          }
          if (row.is_folder === 1) {
            totalFreed += await bfsDeleteNodes(DB, row.id, R2);
          }
          await DB.batch([
            DB.prepare(`DELETE FROM drive_nodes WHERE id = ?`).bind(row.id),
            DB.prepare(`DELETE FROM drive_shares WHERE node_id = ?`).bind(row.id)
          ]);
        }

        if (totalFreed > 0) await updateQuota(DB, -totalFreed);
        return addCors(jsonResponse({
          success: true,
          deleted: (topLevelTrashed.results || []).length,
          freedBytes: totalFreed
        }), env);
      }

      // ================================================================
      // 预览与下载
      // ================================================================

      if (method === 'GET' && (pathname === '/api/file' || pathname === '/api/download')) {
        const filePath = url.searchParams.get('path');
        const node     = await resolvePathToNode(DB, filePath);
        if (!node || node.is_folder === 1 || !node.r2_key) {
          return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);
        }

        if (url.searchParams.get('raw')) {
          if ((node.size || 0) > 2 * 1024 * 1024) {
            return addCors(errorResponse({ message: '文件过大，无法预览', code: 'TOO_LARGE' }, 413), env);
          }
          const object = await R2.get(node.r2_key);
          if (!object) return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);
          return addCors(
            new Response(object.body, { headers: { 'Content-Type': 'text/plain;charset=UTF-8' } }),
            env
          );
        }

        const object = await R2.get(node.r2_key);
        if (!object) return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);

        // 修复：使用 node.name 而非路径字符串，确保文件名正确
        const filename = node.name;
        const headers  = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);
        headers.set('Content-Type', getMimeType(filename));
        headers.set('Accept-Ranges', 'bytes');
        headers.set(
          'Content-Disposition',
          pathname === '/api/download'
            ? `attachment; filename="${encodeURIComponent(filename)}"`
            : `inline; filename="${encodeURIComponent(filename)}"`
        );

        const range = parseByteRange(request.headers.get('Range'), object.size);
        if (range && !range.invalid) {
          const sliced = await R2.get(node.r2_key, { range: { offset: range.start, length: range.length } });
          headers.set('Content-Range', `bytes ${range.start}-${range.end}/${object.size}`);
          headers.set('Content-Length', String(range.length));
          return addCors(new Response(sliced.body, { status: 206, headers }), env);
        }
        headers.set('Content-Length', String(object.size));
        return addCors(new Response(object.body, { status: 200, headers }), env);
      }

      // ================================================================
      // 在线编辑保存
      // ================================================================

      if (method === 'PUT' && pathname === '/api/file') {
        const filePath = url.searchParams.get('path');
        const node     = await resolvePathToNode(DB, filePath);
        if (!node || node.is_folder === 1) {
          return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);
        }

        const content = await request.text();
        if (content.length > 2 * 1024 * 1024) {
          return addCors(errorResponse({ message: '文件过大，无法在线编辑', code: 'TOO_LARGE' }, 413), env);
        }

        const oldSize = node.size || 0;
        const mime    = getMimeType(node.name);
        await R2.put(node.r2_key, content, { httpMetadata: { contentType: mime } });

        const newMeta = await R2.head(node.r2_key);
        if (newMeta) {
          await DB.prepare(
            `UPDATE drive_nodes SET size = ?, updated_at = ? WHERE id = ?`
          ).bind(newMeta.size, new Date().toISOString(), node.id).run();
          await updateQuota(DB, newMeta.size - oldSize);
        }
        return addCors(jsonResponse({ success: true }), env);
      }

      // ================================================================
      // 分享管理
      // ================================================================

      if (method === 'POST' && pathname === '/api/share') {
        const body = await request.json().catch(() => ({}));
        const { paths, expireDays, shareType, password } = body;
        const expiresAt  = expireDays === -1 ? 4102444800000 : Date.now() + expireDays * 24 * 3600 * 1000;
        const urlOrigin  = new URL(request.url).origin;
        const results    = [];
        const now        = new Date().toISOString();

        for (const filePath of (paths || [])) {
          const node = await resolvePathToNode(DB, filePath);
          if (!node) continue;

          const existShare = await DB.prepare(
            `SELECT token, share_type FROM drive_shares WHERE node_id = ? AND expires_at > ?`
          ).bind(node.id, Date.now()).first();

          if (existShare) {
            const shareUrl = existShare.share_type === 'private'
              ? `${urlOrigin}/share/${existShare.token}` // 修复：密码不放 URL
              : `${urlOrigin}/share/${existShare.token}/${encodeURIComponent(filePath)}`;
            results.push({ path: filePath, url: shareUrl, token: existShare.token });
            continue;
          }

          const tok = crypto.randomUUID();
          await DB.prepare(`
            INSERT INTO drive_shares (token, node_id, share_type, password, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(tok, node.id, shareType || 'public', password || null, expiresAt, now).run();

          // 修复：私有分享密码不出现在 URL 中，由前端单独提示用户保存密码
          const shareUrl = shareType === 'private'
            ? `${urlOrigin}/share/${tok}`
            : `${urlOrigin}/share/${tok}/${encodeURIComponent(filePath)}`;

          results.push({ path: filePath, url: shareUrl, token: tok });
        }
        return addCors(jsonResponse({ success: true, shares: results }), env);
      }

      if (method === 'POST' && pathname === '/api/update-share') {
        const body = await request.json().catch(() => ({}));
        const { token, expireDays, password } = body;
        const expiresAt = expireDays === -1 ? 4102444800000 : Date.now() + expireDays * 24 * 3600 * 1000;
        await DB.prepare(
          `UPDATE drive_shares SET expires_at = ?, password = ? WHERE token = ?`
        ).bind(expiresAt, password || null, token).run();
        return addCors(jsonResponse({ success: true }), env);
      }

      if (method === 'GET' && pathname === '/api/shares') {
        const urlOrigin   = new URL(request.url).origin;
        const activeShares = await DB.prepare(`
          SELECT s.token, s.node_id, s.expires_at, s.share_type, n.name, n.size, n.is_folder
          FROM drive_shares s
          JOIN drive_nodes n ON s.node_id = n.id
          WHERE s.expires_at > ?
        `).bind(Date.now()).all();

        // 修复：批量获取路径，减少 N+1 查询（利用 CTE 路径查询）
        const enhanced = await Promise.all((activeShares.results || []).map(async share => {
          const fullPath = await getFullVirtualPath(DB, share.node_id);
          return {
            token:      share.token,
            path:       fullPath,
            expires_at: share.expires_at,
            share_type: share.share_type,
            size:       share.size,
            is_folder:  share.is_folder === 1,
            url: share.share_type === 'private'
              ? `${urlOrigin}/share/${share.token}`
              : `${urlOrigin}/share/${share.token}/${encodeURIComponent(fullPath)}`
          };
        }));

        return addCors(
          jsonResponse(enhanced.sort((a, b) => b.expires_at - a.expires_at)),
          env
        );
      }

      if (method === 'POST' && pathname === '/api/revoke-share') {
        const body = await request.json().catch(() => ({}));
        await DB.prepare(`DELETE FROM drive_shares WHERE token = ?`).bind(body.token).run();
        return addCors(jsonResponse({ success: true }), env);
      }

      // ================================================================
      // 匿名外链下载
      // ================================================================

      if (pathname.startsWith('/share/')) {
        const parts = pathname.split('/').filter(Boolean);
        // parts[0] === 'share'
        if (parts.length < 2) {
          return addCors(errorResponse({ message: '链接格式错误', code: 'BAD_LINK' }, 400), env);
        }

        const tok              = parts[1]; // UUID token
        const providedPassword = url.searchParams.get('pwd') || ''; // 修复：密码通过 query 参数传递

        const share = await DB.prepare(`
          SELECT s.token, s.share_type, s.password, s.expires_at,
                 n.r2_key, n.name, n.is_folder, n.status
          FROM drive_shares s
          JOIN drive_nodes n ON s.node_id = n.id
          WHERE s.token = ?
        `).bind(tok).first();

        if (!share)                     return addCors(errorResponse({ message: '分享失效',             code: 'SHARE_INVALID'  }, 403), env);
        if (share.expires_at < Date.now()) return addCors(errorResponse({ message: '链接已过期',         code: 'SHARE_EXPIRED'  }, 410), env);
        if (share.status !== 'active')     return addCors(errorResponse({ message: '文件已被删除或移至回收站', code: 'FILE_DELETED' }, 404), env);
        if (share.is_folder === 1)         return addCors(errorResponse({ message: '不支持直接下载文件夹', code: 'IS_FOLDER'     }, 400), env);

        if (share.share_type === 'private') {
          const pwdOk = await safeCompare(providedPassword, share.password || '');
          if (!pwdOk) return addCors(errorResponse({ message: '密码错误', code: 'WRONG_PASSWORD' }, 401), env);
        }

        const object = await R2.get(share.r2_key);
        if (!object) return addCors(errorResponse(ErrorCode.FILE_NOT_FOUND, 404), env);

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('Content-Type', getMimeType(share.name));
        headers.set('Content-Length', String(object.size));
        headers.set('Content-Disposition', `attachment; filename="${encodeURIComponent(share.name)}"`);
        return addCors(new Response(object.body, { headers }), env);
      }

      // ================================================================
      // Shared 公共视图
      // ================================================================

      if (pathname === '/shared' || pathname === '/shared/') {
        await ensureFoldersByPath(DB, 'shared');
        const subPath    = normalizeVirtualPath(url.searchParams.get('path') || '');
        const searchPath = subPath ? `shared/${subPath}` : 'shared';
        const targetNode = await resolvePathToNode(DB, searchPath);

        const folders = [], files = [];
        if (targetNode?.id) {
          const children = await DB.prepare(
            `SELECT name, is_folder, size FROM drive_nodes WHERE parent_id = ? AND status = 'active'`
          ).bind(targetNode.id).all();
          for (const row of children.results || []) {
            if (row.is_folder === 1) folders.push(row.name);
            else files.push({ name: row.name, size: row.size });
          }
        }
        const html = renderSharedPage(folders, files, subPath, siteTitle);
        return addCors(
          new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } }),
          env
        );
      }

      if (pathname === '/api/shared-list') {
        const subPath    = normalizeVirtualPath(url.searchParams.get('path') || '');
        const targetNode = await resolvePathToNode(DB, subPath ? `shared/${subPath}` : 'shared');
        const folders = [], files = [];
        if (targetNode?.id) {
          const children = await DB.prepare(
            `SELECT name, is_folder, size FROM drive_nodes WHERE parent_id = ? AND status = 'active'`
          ).bind(targetNode.id).all();
          for (const row of children.results || []) {
            if (row.is_folder === 1) folders.push(row.name);
            else files.push({ name: row.name, size: row.size });
          }
        }
        return addCors(jsonResponse({ folders, files }), env);
      }

      // ================================================================
      // 剪贴板
      // ================================================================

      if (pathname === '/api/clipboard') {
        const id = url.searchParams.get('id') || 'default';
        if (method === 'POST') {
          const bodyStr = await request.text();
          await DB.prepare(
            `INSERT OR REPLACE INTO drive_clipboards (id, data, expires_at) VALUES (?, ?, ?)`
          ).bind(id, bodyStr, Date.now() + 86400000).run();
          return addCors(jsonResponse({ ok: true }), env);
        }
        if (method === 'GET') {
          const row = await DB.prepare(
            `SELECT data FROM drive_clipboards WHERE id = ? AND expires_at > ?`
          ).bind(id, Date.now()).first();
          return addCors(
            jsonResponse(row ? JSON.parse(row.data) : { items: [], action: null, sourcePath: '' }),
            env
          );
        }
        if (method === 'DELETE') {
          await DB.prepare(`DELETE FROM drive_clipboards WHERE id = ?`).bind(id).run();
          return addCors(jsonResponse({ ok: true }), env);
        }
      }

      // ================================================================
      // 备份目录
      // ================================================================

      if (pathname === '/api/backup-dirs') {
        const clientId = url.searchParams.get('clientId') || '';
        if (!clientId && method !== 'POST') {
          return addCors(errorResponse({ message: 'missing clientId', code: 'MISSING_PARAM' }, 400), env);
        }
        if (method === 'GET') {
          const row  = await DB.prepare(`SELECT dirs FROM drive_backup_dirs WHERE client_id = ?`).bind(clientId).first();
          const dirs = row ? JSON.parse(row.dirs) : [];
          return addCors(jsonResponse({ ok: true, dirs, count: dirs.length }), env);
        }
        if (method === 'POST') {
          const body = await request.json().catch(() => ({}));
          await DB.prepare(
            `INSERT OR REPLACE INTO drive_backup_dirs (client_id, dirs) VALUES (?, ?)`
          ).bind(body.clientId, JSON.stringify(Array.isArray(body.dirs) ? body.dirs : [])).run();
          return addCors(jsonResponse({ ok: true }), env);
        }
        if (method === 'DELETE') {
          await DB.prepare(`DELETE FROM drive_backup_dirs WHERE client_id = ?`).bind(clientId).run();
          return addCors(jsonResponse({ ok: true, cleared: true }), env);
        }
      }

      // ================================================================
      // 孤儿文件清理
      // ================================================================

      if (pathname === '/api/orphan-cleanup' && method === 'POST') {
        const body = await request.json().catch(() => ({}));

        if (body.action === 'scan') {
          const referencedRes = await DB.prepare(
            `SELECT r2_key FROM drive_nodes WHERE is_folder = 0 AND r2_key IS NOT NULL`
          ).all();
          const referenced = new Set((referencedRes.results || []).map(r => r.r2_key));

          const orphans = [];
          let cursor, totalSize = 0, totalObjects = 0;
          do {
            const list = await R2.list({ cursor, limit: 1000 });
            for (const obj of list.objects) {
              totalObjects++;
              if (!obj.key.startsWith('.system/') && !referenced.has(obj.key)) {
                orphans.push({ key: obj.key, size: obj.size });
                totalSize += obj.size;
              }
            }
            cursor = list.truncated ? list.cursor : undefined;
          } while (cursor);

          return addCors(jsonResponse({ ok: true, orphans, totalSize, totalObjects }), env);
        }

        if (body.action === 'clean') {
          const keys = Array.isArray(body.keys) ? body.keys : [];
          let deleted = 0, failed = 0, freedBytes = 0;
          for (const key of keys) {
            try {
              const meta = await R2.head(key);
              await R2.delete(key);
              deleted++;
              freedBytes += meta?.size || 0;
            } catch {
              failed++;
            }
          }
          return addCors(jsonResponse({ ok: true, deleted, failed, freedBytes }), env);
        }
      }

      // ================================================================
      // 格式化（危险操作）
      // ================================================================

      if (method === 'POST' && pathname === '/api/format') {
        const body = await request.json().catch(() => ({}));
        if (!body.confirm) return addCors(errorResponse(ErrorCode.UNAUTHORIZED, 403), env);

        // 清空 R2
        let cursor;
        do {
          const list = await R2.list({ cursor, limit: 1000 });
          if (list.objects.length > 0) {
            await Promise.all(list.objects.map(obj => R2.delete(obj.key)));
          }
          cursor = list.truncated ? list.cursor : undefined;
        } while (cursor);

        // 清空 D1
        await DB.batch([
          DB.prepare(`DELETE FROM drive_nodes`),
          DB.prepare(`DELETE FROM drive_shares`),
          DB.prepare(`DELETE FROM drive_settings`),
          DB.prepare(`DELETE FROM drive_uploads`),
          DB.prepare(`DELETE FROM drive_upload_parts`),
          DB.prepare(`DELETE FROM drive_clipboards`)
        ]);
        // 格式化后应显式重置
        await DB.batch([...]);
        await setQuota(DB, 0);  // 明确重置配额
        return addCors(jsonResponse({ success: true }), env);
      }

      // ================================================================
      // 主页（从 R2 加载静态文件）
      // ================================================================

      if (pathname === '/' || pathname === '') {
        const html = await serveStaticFromR2(R2, 'static/index.html', getDefaultPage(siteTitle));
        return addCors(
          new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } }),
          env
        );
      }

      return addCors(new Response('Not Found', { status: 404 }), env);

    } catch (e) {
      console.error('[Worker Error]', e?.stack || e);
      return addCors(
        errorResponse({ message: e?.message || 'Internal Error', code: 'INTERNAL_ERROR' }, 500),
        env
      );
    }
  },

  // ================================================================
  // 定时清理任务
  // ================================================================

  async scheduled(event, env, ctx) {
    const DB = env.DB;
    if (!DB) return;

    // 清理过期分享
    try {
      await DB.prepare(`DELETE FROM drive_shares WHERE expires_at < ?`).bind(Date.now()).run();
    } catch (e) { console.error('scheduled: clean shares', e); }

    // 清理过期剪贴板
    try {
      await DB.prepare(`DELETE FROM drive_clipboards WHERE expires_at < ?`).bind(Date.now()).run();
    } catch (e) { console.error('scheduled: clean clipboards', e); }

    // 清理超过 24h 的未完成上传会话
    try {
      const old = new Date(Date.now() - 86400000).toISOString();
      const expiredUploads = await DB.prepare(
        `SELECT upload_id, node_id FROM drive_uploads WHERE created_at < ?`
      ).bind(old).all();

      for (const row of expiredUploads.results || []) {
        await DB.batch([
          DB.prepare(`DELETE FROM drive_upload_parts WHERE upload_id = ?`).bind(row.upload_id),
          DB.prepare(`DELETE FROM drive_uploads WHERE upload_id = ?`).bind(row.upload_id),
          DB.prepare(`DELETE FROM drive_nodes WHERE id = ? AND status = 'pending'`).bind(row.node_id)
        ]);
      }
    } catch (e) { console.error('scheduled: clean uploads', e); }
  }
};
