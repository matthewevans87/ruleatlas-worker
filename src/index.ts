import { z } from "zod";

export interface Env {
  WAITLIST: KVNamespace;
  ENV?: string;
  ADMIN_TOKEN?: string; // set via `wrangler secret put ADMIN_TOKEN`
}

const WaitlistSchema = z.object({
  email: z.string().email().max(254),
  source: z.string().max(100).optional(),
  utm: z
    .object({
      source: z.string().max(100).optional(),
      medium: z.string().max(100).optional(),
      campaign: z.string().max(100).optional(),
      term: z.string().max(100).optional(),
      content: z.string().max(100).optional(),
    })
    .optional(),
  referrer: z.string().max(500).optional(),
});

function json(data: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function corsHeaders(origin: string | null) {
  // Allow the landing domain + localhost for dev.
  const allow = new Set([
    "https://tryruleatlas.com",
    "https://www.tryruleatlas.com",
    "http://localhost:8787",
    "http://127.0.0.1:8787",
  ]);
  if (origin && allow.has(origin)) {
    return {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type, x-admin-token",
      "access-control-max-age": "86400",
    };
  }
  // No CORS for unknown origins.
  return {};
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("origin");

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405);
    }

    // Admin export (requires secret)
    if (url.pathname === "/admin/export") {
      const token = request.headers.get("x-admin-token") || "";
      if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) {
        return json({ ok: false, error: "unauthorized" }, 401, corsHeaders(origin));
      }

      const rows: Array<{ email: string; ts?: string; source?: string; referrer?: string; utm?: any }> = [];
      let cursor: string | undefined = undefined;
      do {
        const res = await env.WAITLIST.list({ prefix: "email:", cursor, limit: 1000 });
        cursor = res.list_complete ? undefined : res.cursor;
        for (const k of res.keys) {
          const v = await env.WAITLIST.get(k.name);
          if (!v) continue;
          try {
            const parsed = JSON.parse(v);
            rows.push({
              email: parsed.email,
              ts: parsed.ts,
              source: parsed.source,
              referrer: parsed.referrer,
              utm: parsed.utm,
            });
          } catch {
            // ignore
          }
        }
      } while (cursor);

      // CSV output
      const header = ["email", "ts", "source", "referrer", "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"].join(",");
      const lines = rows
        .sort((a, b) => (a.ts || "").localeCompare(b.ts || ""))
        .map((r) => {
          const utm = r.utm || {};
          const cols = [
            r.email || "",
            r.ts || "",
            r.source || "",
            r.referrer || "",
            utm.source || "",
            utm.medium || "",
            utm.campaign || "",
            utm.term || "",
            utm.content || "",
          ].map((x: string) => `"${String(x).replaceAll('"', '""')}"`);
          return cols.join(",");
        });

      return new Response([header, ...lines].join("\n"), {
        status: 200,
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "cache-control": "no-store",
          ...corsHeaders(origin),
        },
      });
    }

    if (url.pathname !== "/waitlist") {
      return json({ ok: false, error: "not_found" }, 404);
    }

    let body: unknown;
    const ct = request.headers.get("content-type") || "";
    try {
      if (ct.includes("application/json")) {
        body = await request.json();
      } else if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) {
        const fd = await request.formData();
        body = {
          email: fd.get("email"),
          source: fd.get("source"),
        };
      } else {
        return json({ ok: false, error: "unsupported_content_type" }, 415, corsHeaders(origin));
      }
    } catch {
      return json({ ok: false, error: "invalid_body" }, 400, corsHeaders(origin));
    }

    const parsed = WaitlistSchema.safeParse(body);
    if (!parsed.success) {
      return json({ ok: false, error: "invalid_email" }, 400, corsHeaders(origin));
    }

    const ip = request.headers.get("cf-connecting-ip") || "";
    const ipHash = await crypto.subtle
      .digest("SHA-256", new TextEncoder().encode(ip))
      .then((b) => Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, "0")).join(""));

    // Lightweight rate limiting: max 20 submissions per IP per hour.
    const hour = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
    const rlKey = `rl:${ipHash}:${hour}`;
    const rlRaw = await env.WAITLIST.get(rlKey);
    const rl = rlRaw ? Number(rlRaw) : 0;
    if (rl >= 20) {
      return json({ ok: false, error: "rate_limited" }, 429, corsHeaders(origin));
    }
    await env.WAITLIST.put(rlKey, String(rl + 1), { expirationTtl: 60 * 60 * 2 });

    const email = parsed.data.email.toLowerCase();
    const key = `email:${email}`;

    // Idempotent: if already present, return ok.
    const existing = await env.WAITLIST.get(key);
    if (!existing) {
      await env.WAITLIST.put(
        key,
        JSON.stringify({
          email,
          source: parsed.data.source || "landing",
          utm: parsed.data.utm || undefined,
          referrer: parsed.data.referrer || origin || "",
          ts: new Date().toISOString(),
          ipHash,
          ua: request.headers.get("user-agent") || "",
        }),
      );
    }

    return json({ ok: true }, 200, corsHeaders(origin));
  },
};
