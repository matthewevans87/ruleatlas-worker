import { z } from "zod";

export interface Env {
  WAITLIST: KVNamespace;
  ENV?: string;
}

const WaitlistSchema = z.object({
  email: z.string().email().max(254),
  source: z.string().max(100).optional(),
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
      "access-control-allow-headers": "content-type",
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
          ts: new Date().toISOString(),
          ipHash: await crypto.subtle
            .digest("SHA-256", new TextEncoder().encode(request.headers.get("cf-connecting-ip") || ""))
            .then((b) => Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, "0")).join("")),
          ua: request.headers.get("user-agent") || "",
        }),
      );
    }

    return json({ ok: true }, 200, corsHeaders(origin));
  },
};
