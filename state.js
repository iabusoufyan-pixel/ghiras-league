// واجهة بيانات دوري غراس
// GET  /api/state                              → آخر نسخة من بيانات الدوري (للجميع)
// POST /api/state {action:"login", pin}        → التحقق من رمز اللجنة
// POST /api/state {action:"save", pin, version, data} → حفظ البيانات (للجنة فقط)
//
// التخزين: Upstash Redis المربوط من Vercel Marketplace.
// المتغيرات المطلوبة في Vercel:
//   KV_REST_API_URL و KV_REST_API_TOKEN  (تُضاف تلقائيًا عند ربط Upstash)
//   COMMITTEE_PIN                         (رمز اللجنة، تضيفه أنت)

import crypto from "node:crypto";

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const PIN = process.env.COMMITTEE_PIN || "";

const KEY_DATA = "ghiras:data";
const KEY_VER = "ghiras:version";
const MAX_BYTES = 900 * 1024;
const MAX_FAILS = 10; // محاولات خاطئة لكل عنوان خلال ١٥ دقيقة
const FAIL_WINDOW = 15 * 60;

// يحفظ فقط إذا لم يحفظ أحد قبلنا (منع الكتابة فوق تعديل عضو آخر)
const SAVE_SCRIPT = `
local v = tonumber(redis.call('GET', KEYS[2]) or '0')
if v ~= tonumber(ARGV[1]) then return -1 end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], v + 1)
return v + 1`;

export async function redis(cmd) {
  const r = await fetch(REDIS_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

function samePin(a) {
  if (!PIN || typeof a !== "string") return false;
  const h = (s) => crypto.createHash("sha256").update(s).digest();
  return crypto.timingSafeEqual(h(a), h(PIN));
}

function clientIp(req) {
  const f = req.headers["x-forwarded-for"];
  return (Array.isArray(f) ? f[0] : f || "").split(",")[0].trim() || "unknown";
}

function validData(d) {
  return (
    d && typeof d === "object" && !Array.isArray(d) &&
    Array.isArray(d.teams) && d.teams.length > 0 &&
    Array.isArray(d.matches)
  );
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") return JSON.parse(req.body || "{}");
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (!REDIS_URL || !REDIS_TOKEN) {
    if (req.method === "GET") return res.status(200).json({ configured: false, version: 0, data: null });
    return res.status(503).json({ error: "قاعدة البيانات غير مربوطة بعد في Vercel" });
  }

  try {
    if (req.method === "GET") {
      const [raw, ver] = await redis(["MGET", KEY_DATA, KEY_VER]);
      return res.status(200).json({
        configured: true,
        version: Number(ver || 0),
        data: raw ? JSON.parse(raw) : null,
      });
    }

    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return res.status(405).json({ error: "طريقة غير مدعومة" });
    }

    let body;
    try { body = await readBody(req); } catch { return res.status(400).json({ error: "طلب غير صالح" }); }

    if (!PIN) return res.status(503).json({ error: "لم يُضبط رمز اللجنة COMMITTEE_PIN في Vercel" });

    const failKey = `ghiras:fail:${clientIp(req)}`;
    const fails = Number((await redis(["GET", failKey])) || 0);
    if (fails >= MAX_FAILS) return res.status(429).json({ error: "محاولات كثيرة، حاول بعد ربع ساعة" });

    if (!samePin(body.pin)) {
      await redis(["INCR", failKey]);
      await redis(["EXPIRE", failKey, FAIL_WINDOW]);
      return res.status(401).json({ error: "الرمز غير صحيح" });
    }

    if (body.action === "login") return res.status(200).json({ ok: true });

    if (body.action === "save") {
      if (!validData(body.data)) return res.status(400).json({ error: "بيانات غير مكتملة" });
      const payload = JSON.stringify(body.data);
      if (Buffer.byteLength(payload) > MAX_BYTES) return res.status(413).json({ error: "حجم البيانات كبير جدًا" });
      const expected = Number(body.version || 0);
      const next = await redis(["EVAL", SAVE_SCRIPT, "2", KEY_DATA, KEY_VER, String(expected), payload]);
      if (Number(next) === -1) return res.status(409).json({ error: "عدّل عضو آخر البيانات قبلك" });
      return res.status(200).json({ ok: true, version: Number(next) });
    }

    return res.status(400).json({ error: "إجراء غير معروف" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "خطأ في الخادم، حاول مرة أخرى" });
  }
}
