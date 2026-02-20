import { describe, expect, test } from "bun:test";
import scanHandler from "../api/scan";

describe("/api/scan", () => {
  test("scans diff and returns summary", async () => {
    const request = new Request("http://localhost/api/scan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        diff: `diff --git a/api/auth.ts b/api/auth.ts
index 1..2 100644
--- a/api/auth.ts
+++ b/api/auth.ts
@@ -1,1 +1,2 @@
+const password = \"my-secret-password\";\n`,
        llm: {
          mode: "off",
        },
      }),
    });

    const response = await scanHandler(request);
    const body = (await response.json()) as {
      summary: { high: number };
      llm: { attempted: boolean };
    };

    expect(response.status).toBe(200);
    expect(body.summary.high).toBeGreaterThan(0);
    expect(body.llm.attempted).toBeFalse();
  });

  test("rejects non-post requests", async () => {
    const response = await scanHandler(new Request("http://localhost/api/scan"));
    expect(response.status).toBe(405);
  });

  test("rejects invalid failOn value", async () => {
    const request = new Request("http://localhost/api/scan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        diff: `diff --git a/api/auth.ts b/api/auth.ts
index 1..2 100644
--- a/api/auth.ts
+++ b/api/auth.ts
@@ -1,1 +1,2 @@
+const password = "my-secret-password";`,
        failOn: "critical",
      }),
    });

    const response = await scanHandler(request);
    const body = (await response.json()) as { error: string };
    expect(response.status).toBe(400);
    expect(body.error).toContain("failOn");
  });

  test("blocks unauthenticated overrides", async () => {
    delete process.env.THREATLENS_API_KEY;

    const request = new Request("http://localhost/api/scan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        diff: `diff --git a/a.ts b/a.ts
index 1..2 100644
--- a/a.ts
+++ b/a.ts
@@ -1,1 +1,2 @@
+const password = "my-secret-password";`,
        overrides: {
          disableRules: ["hardcoded-secret"],
        },
      }),
    });

    const response = await scanHandler(request);
    expect(response.status).toBe(403);
  });
});
