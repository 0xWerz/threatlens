import { describe, expect, test } from "bun:test";
import { parseAddedLines } from "../src/diff";
import { scanDiff, severityMeetsThreshold } from "../src/scanner";

describe("parseAddedLines", () => {
  test("extracts added lines with file and line numbers", () => {
    const diff = `diff --git a/src/app.ts b/src/app.ts
index 123..456 100644
--- a/src/app.ts
+++ b/src/app.ts
@@ -10,2 +10,3 @@ export function run() {
 const a = 1;
+const token = "abc123456789";
 return a;
}`;

    const lines = parseAddedLines(diff);

    expect(lines).toEqual([
      {
        filePath: "src/app.ts",
        line: 11,
        text: 'const token = "abc123456789";',
      },
    ]);
  });
});

describe("scanDiff", () => {
  test("finds high and medium risk patterns", () => {
    const diff = `diff --git a/server/routes.ts b/server/routes.ts
index 111..222 100644
--- a/server/routes.ts
+++ b/server/routes.ts
@@ -1,3 +1,9 @@
 app.get("/login", (req, res) => {
+  const password = "my-secret-password";
+  res.redirect(req.query.next);
+  const agent = new https.Agent({ rejectUnauthorized: false });
+  return password;
 });
`;

    const result = scanDiff(diff);

    expect(result.summary.total).toBeGreaterThanOrEqual(3);
    expect(result.summary.high).toBeGreaterThanOrEqual(2);
    expect(result.findings.some((f) => f.ruleId === "hardcoded-secret")).toBeTrue();
    expect(result.findings.some((f) => f.ruleId === "open-redirect")).toBeTrue();
    expect(
      result.findings.some((f) => f.ruleId === "tls-verification-disabled"),
    ).toBeTrue();
  });

  test("detects wildcard CORS with credentials", () => {
    const diff = `diff --git a/src/cors.ts b/src/cors.ts
index 111..222 100644
--- a/src/cors.ts
+++ b/src/cors.ts
@@ -1,2 +1,6 @@
 app.use(cors({
+  origin: "*",
+  credentials: true,
 }));
`;

    const result = scanDiff(diff);
    expect(
      result.findings.some((f) => f.ruleId === "cors-wildcard-credentials"),
    ).toBeTrue();
  });
});

describe("severity threshold", () => {
  test("matches thresholds correctly", () => {
    expect(severityMeetsThreshold("high", "high")).toBeTrue();
    expect(severityMeetsThreshold("medium", "high")).toBeFalse();
    expect(severityMeetsThreshold("medium", "medium")).toBeTrue();
    expect(severityMeetsThreshold("low", "none")).toBeFalse();
  });
});
