import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

const ALLOWED_PREFIXES = ["api/platform/", "api/copilot/"] as const;
const ALLOWED_GET_EXACT = new Set<string>(["api/models/catalog"]);

function getUpstreamBase(): string {
  const raw =
    process.env.HUNTER_API_BASE ||
    process.env.NEXT_PUBLIC_HUNTER_API_BASE ||
    "http://127.0.0.1:8000";
  return raw.replace(/\/+$/, "");
}

function buildSafeUpstreamUrl(
  segments: string[],
  search: string,
  method: string
): URL | null {
  if (!Array.isArray(segments) || segments.length === 0) {
    return null;
  }
  for (const seg of segments) {
    if (!seg || seg === "." || seg === ".." || !/^[A-Za-z0-9._-]+$/.test(seg)) {
      return null;
    }
  }
  const joined = segments.join("/");
  const isAllowedPrefix = ALLOWED_PREFIXES.some((prefix) => joined.startsWith(prefix));
  const isAllowedGetExact = method === "GET" && ALLOWED_GET_EXACT.has(joined);
  if (!isAllowedPrefix && !isAllowedGetExact) {
    return null;
  }

  const base = getUpstreamBase();
  let baseUrl: URL;
  try {
    baseUrl = new URL(base);
  } catch {
    return null;
  }
  if (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") {
    return null;
  }

  const target = new URL(`${base}/${joined}${search}`);
  if (target.origin !== baseUrl.origin) {
    return null;
  }
  return target;
}

async function handleProxy(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
): Promise<Response> {
  const { path } = await context.params;
  const targetUrl = buildSafeUpstreamUrl(path, request.nextUrl.search, request.method);
  if (!targetUrl) {
    return Response.json(
      { status: "error", error: "Disallowed upstream path" },
      { status: 400 }
    );
  }

  const headers = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) {
    headers.set("content-type", contentType);
  }
  const accept = request.headers.get("accept");
  if (accept) {
    headers.set("accept", accept);
  }
  const lastEventId = request.headers.get("last-event-id");
  if (lastEventId) {
    headers.set("last-event-id", lastEventId);
  }

  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  try {
    const upstream = await fetch(targetUrl.toString(), {
      method: request.method,
      headers,
      body: body && body.byteLength > 0 ? body : undefined,
      signal: request.signal,
      cache: "no-store",
    });

    const respHeaders = new Headers();
    const upstreamType = upstream.headers.get("content-type") || "application/json";
    respHeaders.set("Content-Type", upstreamType);
    if (upstreamType.includes("text/event-stream")) {
      respHeaders.set("Cache-Control", "no-cache, no-transform");
      respHeaders.set("Connection", "keep-alive");
      respHeaders.set("X-Accel-Buffering", "no");
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: respHeaders,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "FastAPI Hub unreachable";
    return Response.json(
      {
        status: "offline",
        online: false,
        error: message,
      },
      { status: 503 }
    );
  }
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  return handleProxy(request, context);
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  return handleProxy(request, context);
}

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  return handleProxy(request, context);
}

export async function PATCH(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  return handleProxy(request, context);
}

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  return handleProxy(request, context);
}
