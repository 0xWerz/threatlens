import { describe, expect, test } from "bun:test";
import { runLlmAdvisoryScan } from "../src/llm";

describe("runLlmAdvisoryScan", () => {
  test("returns disabled state when OPENROUTER_API_KEY is missing", async () => {
    delete process.env.OPENROUTER_API_KEY;

    const result = await runLlmAdvisoryScan({
      diffText: "diff --git a/a.ts b/a.ts\n@@ -1 +1 @@\n+const a = 1",
      deterministicFindings: [],
      options: { mode: "auto" },
    });

    expect(result.enabled).toBeFalse();
    expect(result.attempted).toBeFalse();
    expect(result.findings.length).toBe(0);
  });
});
