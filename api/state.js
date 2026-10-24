// واجهة بيانات دوري غراس
// GET  /api/state                              → آخر نسخة من بيانات الدوري (للجميع)
// GET  /api/state?since=N                      → {same:true} إن لم تتغير النسخة N (فحص خفيف للتحديث الدوري)
// POST /api/state {action:"login", pin}        → التحقق من رمز اللجنة، ويعيد مفتاح جلسة (token)
// POST /api/state {action:"load", token}       → البيانات كاملة (للجنة)
// POST /api/state {action:"save", token, version, data} → حفظ البيانات (للجنة فقط)
// POST /api/state {action:"history", token}    → النسخ السابقة المحفوظة احتياطيًا
// POST /api/state {action:"restore", token, version, v} → استرجاع النسخة v
// POST /api/state {action:"logout", token}     → إنهاء الجلسة
// POST /api/state {action:"vote", poll, option, voter} → صوت في تصويت مفتوح (للجميع، صوت واحد لكل جهاز)
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
const KEY_HIST = "ghiras:history";
const MAX_BYTES = 900 * 1024;
const MAX_FAILS = 10; // محاولات خاطئة لكل عنوان خلال ١٥ دقيقة
const FAIL_WINDOW = 15 * 60;
const SESSION_TTL = 30 * 24 * 60 * 60; // تبقى الجلسة ٣٠ يومًا
const HIST_KEEP = 60; // عدد النسخ الاحتياطية المحفوظة

// يحفظ فقط إذا لم يحفظ أحد قبلنا (منع الكتابة فوق تعديل عضو آخر)،
// ويحفظ النسخة السابقة في سجل احتياطي قبل استبدالها: "رقم النسخة|الوقت|البيانات"
const SAVE_SCRIPT = `
local v = tonumber(redis.call('GET', KEYS[2]) or '0')
if v ~= tonumber(ARGV[1]) then return -1 end
local old = redis.call('GET', KEYS[1])
if old then
  redis.call('LPUSH', KEYS[3], v .. '|' .. ARGV[3] .. '|' .. old)
  redis.call('LTRIM', KEYS[3], 0, tonumber(ARGV[4]) - 1)
end
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

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");

function samePin(a) {
  if (!PIN || typeof a !== "string") return false;
  const h = (s) => crypto.createHash("sha256").update(s).digest();
  return crypto.timingSafeEqual(h(a), h(PIN));
}

// الجلسة مربوطة بالرمز الحالي، فإذا تغيّر COMMITTEE_PIN انتهت كل الجلسات القديمة
async function newSession() {
  const token = crypto.randomBytes(32).toString("base64url");
  await redis(["SET", `ghiras:sess:${sha(token)}`, sha(PIN), "EX", String(SESSION_TTL)]);
  return token;
}
async function validSession(token) {
  if (!PIN || typeof token !== "string" || token.length < 20) return false;
  const v = await redis(["GET", `ghiras:sess:${sha(token)}`]);
  return v === sha(PIN);
}

function clientIp(req) {
  const f = req.headers["x-forwarded-for"];
  return (Array.isArray(f) ? f[0] : f || "").split(",")[0].trim() || "unknown";
}

// ما يراه الطلاب: كل شيء عدا صفقات المزاد ومكافآت التحديات والإكراميات ورسوم الإعارات
function publicView(d) {
  const { transfers, awards, loanLog, bonuses, ...rest } = d || {};
  // الإعارات تظهر للطلاب بلا رسومها
  rest.loanLog = (loanLog || []).map(({ day, slot, p, from, to }) => ({ day, slot, p, from, to }));
  return rest;
}

// عدّادات الأصوات محفوظة خارج بيانات الدوري حتى لا يتعارض التصويت مع حفظ اللجنة
const MAX_VOTES_PER_IP = 40; // شبكة واحدة قد يشترك فيها طلاب الحلقة كلهم
// التصويت سري: الطلاب لا يرون العدّادات إلا لتصويت مغلق أعلنت اللجنة نتيجته
async function pollCounts(data, isPublic) {
  const polls = ((data && data.polls) || []).filter((p) => !isPublic || (p.reveal && !p.open));
  const all = await Promise.all(polls.map((p) => redis(["HGETALL", `ghiras:poll:${p.id}`])));
  const out = {};
  polls.forEach((p, k) => {
    const arr = all[k] || [];
    const c = {};
    for (let i = 0; i < arr.length; i += 2) c[arr[i]] = Number(arr[i + 1]);
    out[p.id] = c;
  });
  return out;
}

// عند حذف تصويت تُحذف عدّاداته وقائمة المصوّتين فيه
async function dropPollKeys(before, after) {
  const keep = new Set(((after && after.polls) || []).map((p) => p.id));
  const gone = ((before && before.polls) || []).map((p) => p.id).filter((id) => !keep.has(id));
  if (gone.length) await redis(["DEL", ...gone.flatMap((id) => [`ghiras:poll:${id}`, `ghiras:pollvoters:${id}`])]);
}

function validData(d) {
  return (
    d && typeof d === "object" && !Array.isArray(d) &&
    Array.isArray(d.teams) && d.teams.length > 0 &&
    Array.isArray(d.matches)
  );
}

function parseHist(s) {
  const a = s.indexOf("|"), b = s.indexOf("|", a + 1);
  return { v: Number(s.slice(0, a)), t: Number(s.slice(a + 1, b)), raw: s.slice(b + 1) };
}

async function writeData(expected, data) {
  const payload = JSON.stringify(data);
  if (Buffer.byteLength(payload) > MAX_BYTES) return { status: 413, error: "حجم البيانات كبير جدًا" };
  const before = await redis(["GET", KEY_DATA]);
  const next = await redis(["EVAL", SAVE_SCRIPT, "3", KEY_DATA, KEY_VER, KEY_HIST, String(expected), payload, String(Date.now()), String(HIST_KEEP)]);
  if (Number(next) === -1) return { status: 409, error: "عدّل عضو آخر البيانات قبلك" };
  if (before) await dropPollKeys(JSON.parse(before), data).catch((e) => console.error(e));
  return { status: 200, version: Number(next) };
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
      const since = req.query && req.query.since;
      if (since != null && since !== "") {
        // أصوات التصويتات المعلنة لا تتغير بعد إغلاقها، فرقم النسخة يكفي لمعرفة التغيير
        const ver = Number((await redis(["GET", KEY_VER])) || 0);
        if (ver === Number(since)) return res.status(200).json({ configured: true, same: true, version: ver });
      }
      const [raw, ver] = await redis(["MGET", KEY_DATA, KEY_VER]);
      const full = raw ? JSON.parse(raw) : null;
      return res.status(200).json({
        configured: true,
        version: Number(ver || 0),
        data: full ? publicView(full) : null,
        votes: full ? await pollCounts(full, true) : {},
        full: false,
      });
    }

    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return res.status(405).json({ error: "طريقة غير مدعومة" });
    }

    let body;
    try { body = await readBody(req); } catch { return res.status(400).json({ error: "طلب غير صالح" }); }

    if (body.action === "vote") {
      const raw = await redis(["GET", KEY_DATA]);
      const data = raw ? JSON.parse(raw) : null;
      const poll = ((data && data.polls) || []).find((p) => p.id === body.poll);
      if (!poll) return res.status(404).json({ error: "التصويت غير موجود" });
      if (!poll.open) return res.status(409).json({ error: "أُغلق هذا التصويت" });
      const opt = Number(body.option);
      if (!Number.isInteger(opt) || opt < 0 || opt >= (poll.options || []).length) return res.status(400).json({ error: "خيار غير صالح" });
      const voter = String(body.voter || "").slice(0, 64);
      if (voter.length < 8) return res.status(400).json({ error: "طلب غير صالح" });
      const ipKey = `ghiras:pollip:${poll.id}:${clientIp(req)}`;
      if (Number((await redis(["GET", ipKey])) || 0) >= MAX_VOTES_PER_IP) return res.status(429).json({ error: "وصلت الأصوات من هذه الشبكة إلى الحد الأعلى" });
      const added = await redis(["SADD", `ghiras:pollvoters:${poll.id}`, voter]);
      if (Number(added) !== 1) return res.status(409).json({ error: "صوّتَّ من قبل في هذا التصويت", already: true });
      await redis(["HINCRBY", `ghiras:poll:${poll.id}`, String(opt), "1"]);
      await redis(["INCR", ipKey]);
      await redis(["EXPIRE", ipKey, 60 * 60 * 24 * 14]);
      return res.status(200).json({ ok: true, votes: await pollCounts(data, true) });
    }

    if (!PIN) return res.status(503).json({ error: "لم يُضبط رمز اللجنة COMMITTEE_PIN في Vercel" });

    if (body.action === "logout") {
      if (typeof body.token === "string") await redis(["DEL", `ghiras:sess:${sha(body.token)}`]);
      return res.status(200).json({ ok: true });
    }

    if (body.action === "login") {
      const failKey = `ghiras:fail:${clientIp(req)}`;
      const fails = Number((await redis(["GET", failKey])) || 0);
      if (fails >= MAX_FAILS) return res.status(429).json({ error: "محاولات كثيرة، حاول بعد ربع ساعة" });
      if (!samePin(body.pin)) {
        await redis(["INCR", failKey]);
        await redis(["EXPIRE", failKey, FAIL_WINDOW]);
        return res.status(401).json({ error: "الرمز غير صحيح" });
      }
      return res.status(200).json({ ok: true, token: await newSession() });
    }

    if (!(await validSession(body.token))) return res.status(401).json({ error: "انتهت الجلسة، ادخل بالرمز مرة أخرى" });

    if (body.action === "load") {
      const [raw, ver] = await redis(["MGET", KEY_DATA, KEY_VER]);
      return res.status(200).json({
        configured: true,
        version: Number(ver || 0),
        data: raw ? JSON.parse(raw) : null,
        votes: raw ? await pollCounts(JSON.parse(raw)) : {},
        full: true,
      });
    }

    if (body.action === "save") {
      if (!validData(body.data)) return res.status(400).json({ error: "بيانات غير مكتملة" });
      const r = await writeData(Number(body.version || 0), body.data);
      if (r.status !== 200) return res.status(r.status).json({ error: r.error });
      return res.status(200).json({ ok: true, version: r.version });
    }

    if (body.action === "history") {
      const list = (await redis(["LRANGE", KEY_HIST, "0", String(HIST_KEEP - 1)])) || [];
      return res.status(200).json({
        items: list.map((s) => {
          const h = parseHist(s);
          let d = {};
          try { d = JSON.parse(h.raw); } catch {}
          return { v: h.v, t: h.t, matches: (d.matches || []).length, transfers: (d.transfers || []).length, loans: (d.loanLog || []).length, polls: (d.polls || []).length, reports: Object.keys(d.reports || {}).length };
        }),
      });
    }

    if (body.action === "restore") {
      const list = (await redis(["LRANGE", KEY_HIST, "0", String(HIST_KEEP - 1)])) || [];
      const hit = list.map(parseHist).find((h) => h.v === Number(body.v));
      if (!hit) return res.status(404).json({ error: "النسخة غير موجودة" });
      const data = JSON.parse(hit.raw);
      if (!validData(data)) return res.status(400).json({ error: "النسخة تالفة" });
      const r = await writeData(Number(body.version || 0), data);
      if (r.status !== 200) return res.status(r.status).json({ error: r.error });
      return res.status(200).json({ ok: true, version: r.version });
    }

    return res.status(400).json({ error: "إجراء غير معروف" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "خطأ في الخادم، حاول مرة أخرى" });
  }
}
