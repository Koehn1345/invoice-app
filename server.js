import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8744;
const PASSWORD = process.env.APP_PASSWORD;
const SECRET = process.env.SESSION_SECRET || PASSWORD || "";
const PROD = process.env.NODE_ENV === "production" || !!process.env.RAILWAY_ENVIRONMENT;

if (!PASSWORD) console.warn("APP_PASSWORD is not set; nobody can sign in until it is.");
if (!process.env.DATABASE_URL) { console.error("DATABASE_URL is not set"); process.exit(1); }

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : undefined,
});

await pool.query(`
  CREATE TABLE IF NOT EXISTS invoices (
    id text PRIMARY KEY,
    data jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS kv (
    key text PRIMARY KEY,
    data jsonb NOT NULL
  );
`);

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());

app.get("/health", async (_req, res) => {
  try { await pool.query("SELECT 1"); res.json({ ok: true }); }
  catch { res.status(500).json({ ok: false }); }
});

/* ---------- auth: one shared password, long-lived signed cookie ---------- */
// The token is derived from the password, so changing APP_PASSWORD signs out every device.
const token = () => crypto.createHmac("sha256", SECRET).update("invoice-auth-v1:" + PASSWORD).digest("hex");
const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const failures = new Map(); // ip -> { count, until }

app.post("/api/login", async (req, res) => {
  const ip = req.ip;
  const f = failures.get(ip);
  if (f && f.until > Date.now()) return res.status(429).json({ error: "Too many tries. Wait a minute and try again." });
  if (!PASSWORD || !same(req.body?.password ?? "", PASSWORD)) {
    const count = (f?.count || 0) + 1;
    failures.set(ip, { count, until: count >= 5 ? Date.now() + 60_000 : 0 });
    await new Promise((r) => setTimeout(r, 700));
    return res.status(401).json({ error: "Wrong password" });
  }
  failures.delete(ip);
  res.cookie("auth", token(), {
    httpOnly: true, sameSite: "lax", secure: PROD,
    maxAge: 1000 * 60 * 60 * 24 * 400, // ~13 months; refreshed on every visit
  });
  res.json({ ok: true });
});

app.post("/api/logout", (_req, res) => { res.clearCookie("auth"); res.json({ ok: true }); });

app.use("/api", (req, res, next) => {
  if (PASSWORD && same(req.cookies.auth ?? "", token())) {
    // keep the cookie fresh so a device that's used now and then never gets signed out
    res.cookie("auth", token(), { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: 1000 * 60 * 60 * 24 * 400 });
    return next();
  }
  res.status(401).json({ error: "Sign in required" });
});

/* ---------- data ---------- */
const getKv = async (key, fallback) => (await pool.query("SELECT data FROM kv WHERE key=$1", [key])).rows[0]?.data ?? fallback;
const setKv = (key, data) =>
  pool.query("INSERT INTO kv (key, data) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data", [key, data]);

app.get("/api/state", async (_req, res) => {
  const [settings, customers, inv] = await Promise.all([
    getKv("settings", null),
    getKv("customers", {}),
    pool.query("SELECT data FROM invoices ORDER BY updated_at DESC"),
  ]);
  res.json({ settings, customers, invoices: inv.rows.map((r) => r.data) });
});

app.put("/api/invoices/:id", async (req, res) => {
  const inv = req.body;
  if (!inv || inv.id !== req.params.id) return res.status(400).json({ error: "Bad invoice" });
  await pool.query(
    `INSERT INTO invoices (id, data, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
    [inv.id, inv],
  );
  res.json({ ok: true });
});

app.delete("/api/invoices/:id", async (req, res) => {
  await pool.query("DELETE FROM invoices WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.put("/api/settings", async (req, res) => { await setKv("settings", req.body || {}); res.json({ ok: true }); });
app.put("/api/customers", async (req, res) => { await setKv("customers", req.body || {}); res.json({ ok: true }); });

// Restore from a backup file: adds invoices that aren't already here, merges customers,
// and takes the backup's settings only when the server has none yet.
app.post("/api/import", async (req, res) => {
  const { settings, customers, invoices } = req.body || {};
  if (!Array.isArray(invoices)) return res.status(400).json({ error: "Bad backup" });
  let added = 0;
  for (const inv of invoices) {
    if (!inv?.id) continue;
    const r = await pool.query("INSERT INTO invoices (id, data) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING", [inv.id, inv]);
    added += r.rowCount;
  }
  if (customers) await setKv("customers", { ...customers, ...(await getKv("customers", {})) });
  if (settings && !(await getKv("settings", null))) await setKv("settings", settings);
  res.json({ ok: true, added });
});

/* ---------- the app itself ---------- */
app.use(express.static(path.join(__dirname, "public"), {
  setHeaders: (res, file) => { if (/\.(html|js|webmanifest)$/.test(file)) res.setHeader("Cache-Control", "no-cache"); },
}));

app.listen(PORT, () => console.log(`Invoices running on http://localhost:${PORT}`));
