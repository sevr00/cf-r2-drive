/**
 * 将 src/index.html 上传到 Cloudflare R2
 * 路径：static/index.html（Worker 从此路径读取首页）
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── 环境变量 ─────────────────────────────────────────────────────
const CF_API_TOKEN  = process.env.CF_API_TOKEN;
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const R2_BUCKET     = process.env.R2_BUCKET_NAME;
const R2_KEY        = "static/index.html";          // Worker 读取路径

if (!CF_API_TOKEN || !CF_ACCOUNT_ID || !R2_BUCKET) {
  console.error("❌ 缺少环境变量: CF_API_TOKEN / CF_ACCOUNT_ID / R2_BUCKET_NAME");
  process.exit(1);
}

// ── 读取本地文件 ─────────────────────────────────────────────────
const htmlPath = resolve(__dirname, "../src/index.html");
let htmlContent;
try {
  htmlContent = readFileSync(htmlPath);
  console.log(`📄 读取文件: ${htmlPath} (${htmlContent.length} bytes)`);
} catch (e) {
  console.error("❌ 读取 index.html 失败:", e.message);
  process.exit(1);
}

// ── 上传到 R2 ────────────────────────────────────────────────────
const url =
  `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}` +
  `/r2/buckets/${R2_BUCKET}/objects/${R2_KEY}`;

console.log(`🚀 上传到 R2: ${url}`);

const res = await fetch(url, {
  method: "PUT",
  headers: {
    Authorization: `Bearer ${CF_API_TOKEN}`,
    "Content-Type": "text/html; charset=UTF-8",
  },
  body: htmlContent,
});

if (!res.ok) {
  const body = await res.text();
  console.error(`❌ 上传失败 [${res.status}]:`, body);
  process.exit(1);
}

console.log(`✅ index.html 已成功上传至 R2 bucket "${R2_BUCKET}" → ${R2_KEY}`);