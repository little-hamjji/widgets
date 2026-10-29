// 노션 「할 일」 DB → data.json (암호화해서 저장, 위젯에서 대표님 암호로만 풀림)
// GitHub Actions에서 1시간마다 실행. 비밀값: NOTION_TOKEN(노션 연동 키), DATA_KEY(위젯 잠금 암호)
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { webcrypto as crypto, createHash } from "node:crypto";

const TOKEN = process.env.NOTION_TOKEN;
const KEY = process.env.DATA_KEY;
const DB = process.env.NOTION_TODO_DB || "c7014489707248d889238a4165a4dc8d";
if (!TOKEN || !KEY) { console.error("NOTION_TOKEN 또는 DATA_KEY 비밀값이 없습니다"); process.exit(1); }

async function queryAll() {
  const rows = []; let cursor;
  do {
    const res = await fetch(`https://api.notion.com/v1/databases/${DB}/query`, {
      method: "POST",
      headers: { Authorization: `Bearer ${TOKEN}`, "Notion-Version": "2022-06-28", "Content-Type": "application/json" },
      body: JSON.stringify({ page_size: 100, ...(cursor ? { start_cursor: cursor } : {}) }),
    });
    if (!res.ok) { console.error("노션 응답 오류", res.status, await res.text()); process.exit(1); }
    const j = await res.json();
    for (const p of j.results) {
      const P = p.properties;
      rows.push({
        t: (P["업무내용"]?.title || []).map(x => x.plain_text).join("") || "(제목 없음)",
        s: P["상태"]?.status?.name || "시작 전",
        y: P["업무 유형"]?.select?.name || null,
        p: P["프로젝트"]?.select?.name || null,
        r: P["우선순위"]?.select?.name || null,
        d: P["날짜"]?.date?.start?.slice(0, 10) || null,
        u: p.url,
      });
    }
    cursor = j.has_more ? j.next_cursor : null;
  } while (cursor);
  return rows;
}

// 한국 시간 기준 오늘
const today = new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10);
const addDays = (d, n) => new Date(Date.parse(d) + n * 864e5).toISOString().slice(0, 10);

function aggregate(rows) {
  const open = r => r.s !== "완료";
  const count = key => { const m = {}; for (const r of rows) if (r[key]) m[r[key]] = (m[r[key]] || 0) + 1; return Object.entries(m).map(([l, v]) => ({ l, v })).sort((a, b) => b.v - a.v); };
  const proj = {};
  for (const r of rows) {
    if (!r.p) continue;
    const o = proj[r.p] ||= { l: r.p, done: 0, total: 0, types: {}, next: null };
    o.total++; if (!open(r)) o.done++;
    if (r.y) o.types[r.y] = (o.types[r.y] || 0) + 1;
    if (open(r) && r.d && r.d >= today && (!o.next || r.d < o.next)) o.next = r.d;
  }
  const month = {};
  for (const r of rows) { if (!r.d) continue; const k = r.d.slice(0, 7); const o = month[k] ||= { l: k, done: 0, total: 0 }; o.total++; if (!open(r)) o.done++; }
  // 위젯에 보낼 할 일: 끝나지 않은 일 전부 + 최근 30일 안에 끝낸 일
  const tasks = rows.filter(r => open(r) || (r.d && r.d >= addDays(today, -30)))
    .sort((a, b) => (a.d || "9999").localeCompare(b.d || "9999"));
  return {
    today,
    total: rows.length,
    done: rows.filter(r => !open(r)).length,
    open: rows.filter(open).length,
    overdue: rows.filter(r => open(r) && r.d && r.d < today).length,
    week: rows.filter(r => open(r) && r.d && r.d >= today && r.d <= addDays(today, 7)).length,
    byType: count("y"),
    byProject: Object.values(proj).map(o => ({ ...o, types: Object.entries(o.types).sort((a, b) => b[1] - a[1]).slice(0, 2).map(x => x[0]) }))
      .sort((a, b) => (b.total - b.done) - (a.total - a.done) || b.total - a.total),
    byMonth: Object.values(month).sort((a, b) => a.l.localeCompare(b.l)),
    tasks,
  };
}

// AES-256-GCM, 키는 DATA_KEY에서 PBKDF2(SHA-256, 150000회)로 만듦 — 위젯의 풀기 코드와 같은 방식
async function encrypt(obj, pass) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj))));
  const b64 = u => Buffer.from(u).toString("base64");
  return { v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}

const data = aggregate(await queryAll());
// 내용이 그대로면 파일을 건드리지 않음(같은 내용 커밋 방지) — 지문은 암호 섞은 해시라 내용은 드러나지 않음
const sum = createHash("sha256").update(KEY + JSON.stringify(data)).digest("hex").slice(0, 16);
const prev = existsSync("data.json") ? JSON.parse(readFileSync("data.json", "utf8")) : null;
if (prev && prev.sum === sum) console.log("변경 없음");
else {
  const out = { ...(await encrypt(data, KEY)), sum, updated: new Date().toISOString() };
  writeFileSync("data.json", JSON.stringify(out) + "\n");
  console.log(`data.json 갱신: 전체 ${data.total}건, 완료 ${data.done}건`);
}
