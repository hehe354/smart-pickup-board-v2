import { env } from "cloudflare:workers";

type Restaurant = { id: string; code: string; name: string; pin_salt: string; pin_hash: string };
type Session = { token: string; restaurant_id: string; expires_at: string };

const json = (body: unknown, status = 200, headers?: HeadersInit) => Response.json(body, { status, headers });
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const pad = (number: number) => String(number).padStart(3, "0");
const loginKey = (request: Request, code: string) => `${request.headers.get("CF-Connecting-IP") ?? "unknown"}:${code}`;
const isUniqueConstraint = (error: unknown) => error instanceof Error && /unique|constraint/i.test(error.message);

function cookie(request: Request, name: string) {
  return request.headers.get("cookie")?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}
function hex(bytes: Uint8Array) { return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join(""); }
function fromHex(value: string) { return Uint8Array.from(value.match(/.{1,2}/g) ?? [], (byte) => Number.parseInt(byte, 16)); }
async function hashPin(pin: string, salt: string) {
  // `subtle.digest` is available in every Workers runtime. Store only a salted
  // one-way digest; the PIN itself is never written to D1.
  const material = new TextEncoder().encode(`${salt}:${pin}`);
  const digest = await crypto.subtle.digest("SHA-256", material);
  return hex(new Uint8Array(digest));
}
async function body(request: Request) { return (await request.json()) as Record<string, unknown>; }
function auditStatement(input: { restaurantId: string; cycleId?: string | null; pickupNumber?: number | null; action: string; oldStatus?: string | null; newStatus?: string | null; createdAt?: string }) {
  return env.DB.prepare("INSERT INTO audit_logs (id, restaurant_id, cycle_id, pickup_number, action, old_status, new_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id(), input.restaurantId, input.cycleId ?? null, input.pickupNumber ?? null, input.action, input.oldStatus ?? null, input.newStatus ?? null, input.createdAt ?? now());
}
async function recordAudit(input: Parameters<typeof auditStatement>[0]) {
  // Audit data must never make a confirmed pickup look like it failed.
  try { await auditStatement(input).run(); }
  catch (error) { console.error({ event: "pickup_board_audit_failed", message: error instanceof Error ? error.message : String(error) }); }
}

async function getRestaurant(request: Request): Promise<Restaurant | null> {
  const token = cookie(request, "pickup_session");
  if (!token) return null;
  const session = await env.DB.prepare("SELECT token, restaurant_id, expires_at FROM sessions WHERE token = ?").bind(token).first<Session>();
  if (!session || new Date(session.expires_at).getTime() < Date.now()) return null;
  // Board clients poll for changes. Renew only sessions close to expiry so
  // synchronization does not create a database write on every poll.
  if (new Date(session.expires_at).getTime() < Date.now() + 60 * 60 * 1000) {
    await env.DB.prepare("UPDATE sessions SET expires_at = ? WHERE token = ?").bind(new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(), token).run();
  }
  return env.DB.prepare("SELECT id, code, name, pin_salt, pin_hash FROM restaurants WHERE id = ?").bind(session.restaurant_id).first<Restaurant>();
}
async function activeCycle(restaurantId: string) {
  return env.DB.prepare("SELECT id, restaurant_id, number, status, started_at, ended_at FROM cycles WHERE restaurant_id = ? AND status = 'active' LIMIT 1").bind(restaurantId).first<{ id: string; restaurant_id: string; number: number; status: string; started_at: string; ended_at: string | null }>();
}
async function newCycle(restaurantId: string) {
  // The unique partial index in the database is the final guard. This retry
  // simply returns the cycle another iPad created milliseconds earlier.
  const existing = await activeCycle(restaurantId);
  if (existing) return existing;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const next = await env.DB.prepare("SELECT COALESCE(MAX(number), 0) + 1 AS number FROM cycles WHERE restaurant_id = ?").bind(restaurantId).first<{ number: number }>();
    const cycle = { id: id(), restaurantId, number: next?.number ?? 1, startedAt: now() };
    try {
      await env.DB.prepare("INSERT INTO cycles (id, restaurant_id, number, status, started_at) VALUES (?, ?, ?, 'active', ?)").bind(cycle.id, cycle.restaurantId, cycle.number, cycle.startedAt).run();
      return cycle;
    } catch (error) {
      const concurrentlyCreated = await activeCycle(restaurantId);
      if (concurrentlyCreated) return concurrentlyCreated;
      if (!isUniqueConstraint(error) || attempt === 2) throw error;
    }
  }
  throw new Error("CYCLE_CREATE_FAILED");
}
async function requireRestaurant(request: Request) {
  const restaurant = await getRestaurant(request);
  if (!restaurant) throw new Error("UNAUTHORIZED");
  return restaurant;
}
function setSession(token: string) { return `pickup_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`; }

export async function GET(request: Request, context: { params: Promise<{ path: string[] }> }) {
  try {
    const path = (await context.params).path.join("/");
    if (path === "health") {
      try {
        await env.DB.prepare("SELECT 1 FROM restaurants LIMIT 1").first();
        return json({ ok: true, database: "ready" });
      } catch (error) {
        console.error("pickup-board database health check failed", error);
        return json({ ok: false, database: "unavailable" }, 503);
      }
    }
    const restaurant = await requireRestaurant(request);
    if (path === "board") {
      const cycle = (await activeCycle(restaurant.id)) ?? await newCycle(restaurant.id);
      const records = await env.DB.prepare("SELECT pickup_number, status, updated_at FROM pickup_records WHERE cycle_id = ?").bind(cycle.id).all<{ pickup_number: number; status: string; updated_at: string }>();
      return json({ restaurant: { code: restaurant.code, name: restaurant.name }, cycle: { id: cycle.id, number: cycle.number, status: "active", startedAt: cycle.started_at ?? cycle.startedAt }, records: records.results.map((record) => ({ pickupNumber: record.pickup_number, status: record.status, updatedAt: record.updated_at })) });
    }
    if (path === "history") {
      const completed = await env.DB.prepare("SELECT id, number, ended_at FROM cycles WHERE restaurant_id = ? AND status = 'completed' ORDER BY number DESC LIMIT 30").bind(restaurant.id).all<{ id: string; number: number; ended_at: string }>();
      const history = await Promise.all(completed.results.map(async (cycle) => {
        const pending = await env.DB.prepare("SELECT pickup_number FROM pickup_records WHERE cycle_id = ? AND status = 'waiting' ORDER BY pickup_number").bind(cycle.id).all<{ pickup_number: number }>();
        return { number: cycle.number, endedAt: cycle.ended_at, uncollected: pending.results.map((record) => record.pickup_number) };
      }));
      return json({ history });
    }
    if (path === "audit") {
      const events = await env.DB.prepare("SELECT cycle_id, pickup_number, action, old_status, new_status, created_at FROM audit_logs WHERE restaurant_id = ? ORDER BY created_at DESC LIMIT 50").bind(restaurant.id).all<{ cycle_id: string | null; pickup_number: number | null; action: string; old_status: string | null; new_status: string | null; created_at: string }>();
      const summary = await env.DB.prepare("SELECT action, COUNT(*) AS count FROM audit_logs WHERE restaurant_id = ? AND date(created_at, '+8 hours') = date('now', '+8 hours') GROUP BY action ORDER BY action").bind(restaurant.id).all<{ action: string; count: number }>();
      return json({ events: events.results.map((event) => ({ cycleId: event.cycle_id, pickupNumber: event.pickup_number, action: event.action, oldStatus: event.old_status, newStatus: event.new_status, createdAt: event.created_at })), today: summary.results });
    }
    return json({ error: "找不到 API" }, 404);
  } catch (error) {
    console.error({ event: "pickup_board_get_failed", message: error instanceof Error ? error.message : String(error) });
    return json({ error: error instanceof Error && error.message === "UNAUTHORIZED" ? "請先登入" : "暫時未能讀取資料，請稍後再試", retryable: true }, error instanceof Error && error.message === "UNAUTHORIZED" ? 401 : 503);
  }
}

export async function POST(request: Request, context: { params: Promise<{ path: string[] }> }) {
  try {
    const path = (await context.params).path.join("/");
    if (path === "register") {
      const payload = await body(request); const code = String(payload.code ?? "").trim(); const name = String(payload.name ?? "").trim(); const pin = String(payload.pin ?? "");
      if (!/^\d{3}$/.test(code)) return json({ error: "餐廳號碼須為 3 位數字，例如 000" }, 400);
      if (name.length < 2 || name.length > 60) return json({ error: "餐廳名稱須為 2–60 個字元" }, 400);
      if (!/^\d{4,8}$/.test(pin)) return json({ error: "PIN 須為 4–8 位數字" }, 400);
      const existing = await env.DB.prepare("SELECT id FROM restaurants WHERE code = ?").bind(code).first();
      if (existing) return json({ error: "餐廳號碼已存在，請直接登入" }, 409);
      const salt = hex(crypto.getRandomValues(new Uint8Array(16))); const restaurantId = id(); const createdAt = now();
      let pinHash: string;
      try {
        pinHash = await hashPin(pin, salt);
      } catch (error) {
        console.error("pickup-board PIN hashing failed", error);
        return json({ error: "PIN 加密設定發生錯誤，請稍後再試" }, 500);
      }
      try {
        await env.DB.prepare("INSERT INTO restaurants (id, code, name, pin_salt, pin_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(restaurantId, code, name, salt, pinHash, createdAt).run();
        await newCycle(restaurantId);
      } catch (error) {
        console.error("pickup-board restaurant registration write failed", error);
        return json({ error: "無法建立餐廳紀錄，請使用另一個餐廳號碼或稍後再試" }, 500);
      }
      return json({ ok: true }, 201);
    }
    if (path === "login") {
      const payload = await body(request); const code = String(payload.code ?? "").trim(); const pin = String(payload.pin ?? "");
      const key = loginKey(request, code); const attempt = await env.DB.prepare("SELECT failed_count, window_started_at, locked_until FROM login_attempts WHERE key = ?").bind(key).first<{ failed_count: number; window_started_at: string; locked_until: string | null }>();
      if (attempt?.locked_until && new Date(attempt.locked_until).getTime() > Date.now()) return json({ error: "嘗試次數過多，請 15 分鐘後再試" }, 429);
      const restaurant = await env.DB.prepare("SELECT id, code, name, pin_salt, pin_hash FROM restaurants WHERE code = ?").bind(code).first<Restaurant>();
      if (!restaurant || await hashPin(pin, restaurant.pin_salt) !== restaurant.pin_hash) {
        const withinWindow = attempt && Date.now() - new Date(attempt.window_started_at).getTime() < 15 * 60 * 1000;
        const failedCount = withinWindow ? attempt.failed_count + 1 : 1; const startedAt = withinWindow ? attempt.window_started_at : now(); const lockedUntil = failedCount >= 5 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null;
        await env.DB.prepare("INSERT INTO login_attempts (key, failed_count, window_started_at, locked_until) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET failed_count = excluded.failed_count, window_started_at = excluded.window_started_at, locked_until = excluded.locked_until").bind(key, failedCount, startedAt, lockedUntil).run();
        return json({ error: lockedUntil ? "嘗試次數過多，請 15 分鐘後再試" : "餐廳號碼或 PIN 不正確" }, lockedUntil ? 429 : 401);
      }
      await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind(key).run();
      const token = hex(crypto.getRandomValues(new Uint8Array(32)));
      await env.DB.prepare("INSERT INTO sessions (token, restaurant_id, expires_at) VALUES (?, ?, ?)").bind(token, restaurant.id, new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString()).run();
      await recordAudit({ restaurantId: restaurant.id, action: "login" });
      return json({ ok: true }, 200, { "Set-Cookie": setSession(token) });
    }
    if (path === "logout") { const token = cookie(request, "pickup_session"); if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run(); return json({ ok: true }, 200, { "Set-Cookie": "pickup_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" }); }
    const restaurant = await requireRestaurant(request);
    if (path === "records") {
      const payload = await body(request); const number = Number(payload.pickupNumber); const mode = String(payload.mode ?? "record");
      if (!Number.isInteger(number) || number < 0 || number > 999) return json({ error: "號碼必須是 0–999" }, 400);
      const cycle = (await activeCycle(restaurant.id)) ?? await newCycle(restaurant.id); const timestamp = now();
      const existing = await env.DB.prepare("SELECT id, status FROM pickup_records WHERE cycle_id = ? AND pickup_number = ?").bind(cycle.id, number).first<{ id: string; status: string }>();
      let status = "collected"; let duplicateCollected = false;
      if (mode === "toggle") {
        // A single UPSERT makes a tap safe even if two iPads reach D1 together.
        const updated = await env.DB.prepare("INSERT INTO pickup_records (id, restaurant_id, cycle_id, pickup_number, status, recorded_at, updated_at, collected_at) VALUES (?, ?, ?, ?, 'collected', ?, ?, ?) ON CONFLICT(cycle_id, pickup_number) DO UPDATE SET status = CASE WHEN pickup_records.status = 'collected' THEN 'waiting' ELSE 'collected' END, updated_at = excluded.updated_at, collected_at = CASE WHEN pickup_records.status = 'collected' THEN NULL ELSE excluded.collected_at END RETURNING status")
          .bind(id(), restaurant.id, cycle.id, number, timestamp, timestamp, timestamp).first<{ status: string }>();
        status = updated?.status === "waiting" ? "waiting" : "collected";
        await recordAudit({ restaurantId: restaurant.id, cycleId: cycle.id, pickupNumber: number, action: status === "collected" ? "marked_collected" : "marked_waiting", oldStatus: existing?.status ?? null, newStatus: status, createdAt: timestamp });
      } else {
        duplicateCollected = existing?.status === "collected";
        await env.DB.prepare("INSERT INTO pickup_records (id, restaurant_id, cycle_id, pickup_number, status, recorded_at, updated_at, collected_at) VALUES (?, ?, ?, ?, 'collected', ?, ?, ?) ON CONFLICT(cycle_id, pickup_number) DO UPDATE SET status = 'collected', updated_at = excluded.updated_at, collected_at = excluded.collected_at")
          .bind(id(), restaurant.id, cycle.id, number, timestamp, timestamp, timestamp).run();
        await recordAudit({ restaurantId: restaurant.id, cycleId: cycle.id, pickupNumber: number, action: duplicateCollected ? "duplicate_collected" : "recorded_collected", oldStatus: existing?.status ?? null, newStatus: "collected", createdAt: timestamp });
      }
      const message = duplicateCollected ? `${pad(number)} 已經取餐` : `${pad(number)} ${status === "collected" ? "已取餐" : "改為未取餐"}`;
      return json({ record: { pickupNumber: number, status, updatedAt: timestamp }, message, duplicateCollected });
    }
    if (path === "cycles/complete") {
      const cycle = await activeCycle(restaurant.id); if (!cycle) return json({ error: "沒有進行中的輪次" }, 409);
      const pending = await env.DB.prepare("SELECT pickup_number FROM pickup_records WHERE cycle_id = ? AND status = 'waiting' ORDER BY pickup_number").bind(cycle.id).all<{ pickup_number: number }>();
      const completedAt = now();
      await env.DB.prepare("UPDATE cycles SET status = 'completed', ended_at = ? WHERE id = ? AND status = 'active'").bind(completedAt, cycle.id).run();
      await recordAudit({ restaurantId: restaurant.id, cycleId: cycle.id, action: "cycle_completed", createdAt: completedAt });
      const next = await newCycle(restaurant.id);
      return json({ completedCycle: cycle.number, uncollected: pending.results.map((record) => record.pickup_number), nextCycle: next.number });
    }
    if (path === "restaurant/clear-records") {
      const payload = await body(request); if (await hashPin(String(payload.pin ?? ""), restaurant.pin_salt) !== restaurant.pin_hash) return json({ error: "PIN 不正確，沒有清除任何紀錄" }, 403);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM pickup_records WHERE restaurant_id = ?").bind(restaurant.id),
        env.DB.prepare("DELETE FROM cycles WHERE restaurant_id = ?").bind(restaurant.id),
      ]);
      const cycle = await newCycle(restaurant.id);
      await recordAudit({ restaurantId: restaurant.id, cycleId: cycle.id, action: "records_cleared" });
      return json({ ok: true, cycle: cycle.number });
    }
    return json({ error: "找不到 API" }, 404);
  } catch (error) {
    console.error({ event: "pickup_board_post_failed", message: error instanceof Error ? error.message : String(error) });
    return json({ error: error instanceof Error && error.message === "UNAUTHORIZED" ? "請先登入" : "暫時未能保存，請稍後再試", retryable: true }, error instanceof Error && error.message === "UNAUTHORIZED" ? 401 : 503);
  }
}
