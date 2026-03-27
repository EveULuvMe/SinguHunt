import worker, {
  buildCanonicalContext,
  proxyRequest,
  signContext,
  type Env,
} from "../cloudflare-proxy/src/index.ts";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

type CapturedRequest = {
  url: string;
  method: string;
  headers: Headers;
  body: string;
};

async function captureUpstreamRequest(
  request: Request,
  env: Env,
): Promise<{ response: Response; captured: CapturedRequest | null }> {
  const originalFetch = globalThis.fetch;
  let captured: CapturedRequest | null = null;

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const upstreamRequest =
      input instanceof Request ? input : new Request(input, init);
    captured = {
      url: upstreamRequest.url,
      method: upstreamRequest.method,
      headers: new Headers(upstreamRequest.headers),
      body: await upstreamRequest.clone().text(),
    };
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  try {
    const response = await proxyRequest(request, env);
    return { response, captured };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function testProtectedRouteInjectsTrustedHeaders(env: Env) {
  const now = 1_710_000_000_000;
  const originalNow = Date.now;
  Date.now = () => now;

  try {
    const body = JSON.stringify({ playerAddress: "0xabc", ballIndex: 0, epoch: 1 });
    const request = new Request(
      "https://worker.example.com/api/gates/singu-mini-001/claim-ticket",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-ef-assembly-id": "0xdeadbeef",
          "x-ef-tenant": "evil",
          "x-ef-context-ts": "1",
          "x-ef-context-sig": "forged",
        },
        body,
      },
    );

    const originalFetch = globalThis.fetch;
    let captured: CapturedRequest | null = null;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const upstreamRequest =
        input instanceof Request ? input : new Request(input, init);
      captured = {
        url: upstreamRequest.url,
        method: upstreamRequest.method,
        headers: new Headers(upstreamRequest.headers),
        body: await upstreamRequest.clone().text(),
      };
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    let response: Response;
    try {
      response = await worker.fetch(request, env);
    } finally {
      globalThis.fetch = originalFetch;
    }

    assert(response.status === 200, "claim-ticket request should be proxied");
    assert(captured, "upstream request should be captured");
    assert(
      captured.url ===
        "https://dapp.example.com/api/gates/singu-mini-001/claim-ticket",
      "upstream URL should point to configured origin",
    );
    assert(captured.method === "POST", "HTTP method should be preserved");
    assert(captured.body === body, "request body should be preserved");

    const expectedAssemblyId =
      "0x0000000000000000000000000000000000000000000000000000000000000123";
    const expectedSignature = await signContext({
      gateSlug: "singu-mini-001",
      assemblyId: expectedAssemblyId,
      tenant: "utopia",
      timestampMs: now,
      secret: env.EF_CONTEXT_SHARED_SECRET,
    });

    assert(
      captured.headers.get("x-ef-assembly-id") === expectedAssemblyId,
      "proxy should overwrite assembly id with trusted value",
    );
    assert(
      captured.headers.get("x-ef-tenant") === "utopia",
      "proxy should overwrite tenant with trusted value",
    );
    assert(
      captured.headers.get("x-ef-context-ts") === String(now),
      "proxy should inject current timestamp",
    );
    assert(
      captured.headers.get("x-ef-context-sig") === expectedSignature,
      "proxy should inject a valid HMAC signature",
    );
  } finally {
    Date.now = originalNow;
  }
}

async function testDeliverRouteUsesSameProtection(env: Env) {
  const request = new Request(
    "https://worker.example.com/api/gates/singu-mini-001/deliver-ticket",
    { method: "POST", body: JSON.stringify({ ticket: "demo" }) },
  );
  const { response, captured } = await captureUpstreamRequest(request, env);

  assert(response.status === 200, "deliver-ticket request should be proxied");
  assert(captured, "deliver upstream request should be captured");
  assert(
    captured.headers.has("x-ef-context-sig"),
    "deliver-ticket route should also receive trusted signature headers",
  );
}

async function testUnknownGateReturns404(env: Env) {
  const response = await proxyRequest(
    new Request("https://worker.example.com/api/gates/unknown/claim-ticket", {
      method: "POST",
    }),
    env,
  );
  assert(response.status === 404, "unknown gate should return 404");
}

async function testPublicRoutesDoNotInjectHeaders(env: Env) {
  const request = new Request("https://worker.example.com/gates/singu-mini-001?v=2");
  const { response, captured } = await captureUpstreamRequest(request, env);

  assert(response.status === 200, "page route should be proxied");
  assert(captured, "page route should reach upstream");
  assert(
    !captured.headers.has("x-ef-assembly-id"),
    "page routes must not receive trusted claim headers",
  );
  assert(
    captured.url === "https://dapp.example.com/gates/singu-mini-001?v=2",
    "page routes should preserve path and query string",
  );
}

async function main() {
  const env: Env = {
    EF_CONTEXT_SHARED_SECRET: "test-shared-secret",
    TRUSTED_GATE_MAP: JSON.stringify({
      "singu-mini-001": {
        assemblyId: "0x123",
        tenant: "utopia",
      },
    }),
    TRUSTED_TENANT: "utopia",
    UPSTREAM_ORIGIN: "https://dapp.example.com",
  };

  await testProtectedRouteInjectsTrustedHeaders(env);
  await testDeliverRouteUsesSameProtection(env);
  await testUnknownGateReturns404(env);
  await testPublicRoutesDoNotInjectHeaders(env);

  const canonical = buildCanonicalContext({
    gateSlug: "singu-mini-001",
    assemblyId: "0x0000000000000000000000000000000000000000000000000000000000000123",
    tenant: "utopia",
    timestampMs: 1_710_000_000_000,
  });
  console.log("secure-claim smoke checks passed");
  console.log(canonical);
}
await main();
