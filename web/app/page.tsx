"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type Severity = "low" | "medium" | "high";

type Finding = {
    ruleId: string;
    title: string;
    severity: Severity;
    description: string;
    filePath: string;
    line: number;
    evidence: string;
    source?: "rule" | "llm";
    confidence?: number;
};

type Summary = {
    total: number;
    high: number;
    medium: number;
    low: number;
};

type PolicyPack = {
    id: string;
    name: string;
    defaultFailOn: "none" | Severity;
};

type ScanResponse = {
    policy: {
        id: string;
        failOn: "none" | Severity;
    };
    shouldBlock: boolean;
    summary: Summary;
    deterministicSummary?: Summary;
    findings: Finding[];
    error?: string;
};

const sampleDiff = `diff --git a/api/auth.ts b/api/auth.ts
index b11c0de..f00dbab 100644
--- a/api/auth.ts
+++ b/api/auth.ts
@@ -12,6 +12,10 @@ export async function login(req, res) {
   const user = await db.user.findUnique({ where: { email: req.body.email } });
+  const password = "super-secret-password";
+  const agent = new https.Agent({ rejectUnauthorized: false });
+  if (process.env.DEBUG === "1") req.authDisabled = true;
+  return res.redirect(req.query.next);
   if (!user) return res.status(401).json({ ok: false });
   return res.json({ ok: true });
 }`;

export default function Home() {
    const apiBase = useMemo(() => {
        return (
            process.env.NEXT_PUBLIC_THREATLENS_API_URL?.replace(/\/$/, "") || ""
        );
    }, []);

    const [packs, setPacks] = useState<PolicyPack[]>([]);
    const [packId, setPackId] = useState("startup-default");
    const [failOn, setFailOn] = useState<"none" | Severity>("high");
    const [diff, setDiff] = useState("");
    const [summary, setSummary] = useState<Summary | null>(null);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [scanMeta, setScanMeta] = useState("Awaiting input.");
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        async function loadPacks() {
            try {
                const response = await fetch(`${apiBase}/api/packs`);
                if (!response.ok) {
                    throw new Error("Failed to load packs");
                }

                const data = (await response.json()) as { packs: PolicyPack[] };
                const nextPacks = data.packs ?? [];
                setPacks(nextPacks);

                const first = nextPacks[0];
                if (first) {
                    setPackId(first.id);
                    setFailOn(first.defaultFailOn);
                }
            } catch {
                setPacks([
                    {
                        id: "startup-default",
                        name: "Startup Default",
                        defaultFailOn: "high",
                    },
                ]);
                setScanMeta("Using fallback policy pack.");
            }
        }

        loadPacks();
    }, [apiBase]);

    async function onSubmit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();

        const normalized = diff.trim();
        if (!normalized) {
            setScanMeta("Paste a diff first.");
            return;
        }

        setIsLoading(true);
        setScanMeta("Running policy checks…");

        try {
            const response = await fetch(`${apiBase}/api/scan`, {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                },
                body: JSON.stringify({
                    diff: normalized,
                    packId,
                    failOn,
                    llm: {
                        mode: "off",
                    },
                }),
            });

            const data = (await response.json()) as ScanResponse;
            if (!response.ok) {
                throw new Error(data.error || "Scan failed");
            }

            setSummary(data.summary);
            setFindings(data.findings);
            const blockState = data.shouldBlock ? "BLOCK" : "PASS";
            setScanMeta(
                `${data.policy.id} · fail-on:${data.policy.failOn} · ${blockState} · det-high:${data.deterministicSummary?.high ?? 0}`,
            );
        } catch (error) {
            const message =
                error instanceof Error ? error.message : "Scan failed";
            setScanMeta(message);
            setSummary(null);
            setFindings([]);
        } finally {
            setIsLoading(false);
        }
    }

    function loadSample(): void {
        setDiff(sampleDiff);
    }

    const severityIcon = (severity: Severity) => {
        switch (severity) {
            case "high":
                return "▲";
            case "medium":
                return "◆";
            case "low":
                return "●";
        }
    };

    return (
        <div className="page-wrapper">
            <div className="noise" />

            <header className="hero">
                <p className="eyebrow">PR Security Guardrails</p>
                <h1>
                    ThreatLens
                    <span>
                        Scan every diff before it merges. Catch hardcoded
                        secrets, insecure configs, and broken auth logic that
                        generic scanners miss.
                    </span>
                </h1>
                <div className="hero-tags">
                    <span>Diff-first scanning</span>
                    <span>Custom policy packs</span>
                    <span>Zero false positives</span>
                </div>
            </header>

            <main className="layout">
                <section className="panel control-panel">
                    <div className="panel-head">
                        <h2>Run a scan</h2>
                        <p>
                            Paste a unified diff and execute the active policy
                            pack.
                        </p>
                    </div>

                    <form className="scan-form" onSubmit={onSubmit}>
                        <label htmlFor="pack">Policy pack</label>
                        <select
                            id="pack"
                            name="pack"
                            value={packId}
                            onChange={(event) => {
                                const next = event.target.value;
                                setPackId(next);
                                const selected = packs.find(
                                    (pack) => pack.id === next,
                                );
                                if (selected) {
                                    setFailOn(selected.defaultFailOn);
                                }
                            }}
                        >
                            {packs.map((pack) => (
                                <option key={pack.id} value={pack.id}>
                                    {pack.name} ({pack.id})
                                </option>
                            ))}
                        </select>

                        <label htmlFor="failOn">Fail threshold</label>
                        <select
                            id="failOn"
                            name="failOn"
                            value={failOn}
                            onChange={(event) =>
                                setFailOn(
                                    event.target.value as "none" | Severity,
                                )
                            }
                        >
                            <option value="none">none (report-only)</option>
                            <option value="low">low</option>
                            <option value="medium">medium</option>
                            <option value="high">high</option>
                        </select>

                        <label htmlFor="diff">Unified diff</label>
                        <textarea
                            id="diff"
                            name="diff"
                            placeholder="$ git diff HEAD~1 | pbcopy"
                            spellCheck={false}
                            required
                            value={diff}
                            onChange={(event) => setDiff(event.target.value)}
                        />

                        <div className="actions">
                            <button type="submit" disabled={isLoading}>
                                {isLoading ? "Scanning…" : "Scan diff"}
                            </button>
                            <button
                                type="button"
                                className="ghost"
                                onClick={loadSample}
                                disabled={isLoading}
                            >
                                Load sample
                            </button>
                        </div>
                    </form>
                </section>

                <section className="panel results-panel">
                    <div className="panel-head">
                        <h2>Findings</h2>
                        <p>{scanMeta}</p>
                    </div>

                    {summary ? (
                        <div className="summary">
                            <div className="summary-item">
                                <strong>{summary.total}</strong>
                                <span>total</span>
                            </div>
                            <div className="summary-item">
                                <strong style={{ color: "var(--high)" }}>
                                    {summary.high}
                                </strong>
                                <span>high</span>
                            </div>
                            <div className="summary-item">
                                <strong style={{ color: "var(--medium)" }}>
                                    {summary.medium}
                                </strong>
                                <span>medium</span>
                            </div>
                            <div className="summary-item">
                                <strong style={{ color: "var(--low)" }}>
                                    {summary.low}
                                </strong>
                                <span>low</span>
                            </div>
                        </div>
                    ) : null}

                    <div className="findings">
                        {findings.length === 0 ? (
                            <div className="empty">
                                No findings yet — paste a diff and run the
                                scanner.
                            </div>
                        ) : (
                            findings.map((finding) => (
                                <article
                                    key={`${finding.ruleId}-${finding.filePath}-${finding.line}-${finding.evidence}`}
                                    className={`finding ${finding.severity}`}
                                >
                                    <h4>
                                        {severityIcon(finding.severity)} [
                                        {finding.severity.toUpperCase()}]{" "}
                                        {finding.title}
                                    </h4>
                                    <div className="meta">
                                        {finding.ruleId} · {finding.filePath}:
                                        {finding.line}
                                        {finding.source
                                            ? ` · ${finding.source}`
                                            : ""}
                                        {typeof finding.confidence === "number"
                                            ? ` · conf ${Math.round(finding.confidence * 100)}%`
                                            : ""}
                                    </div>
                                    <div className="meta">
                                        {finding.description}
                                    </div>
                                    <pre className="evidence">
                                        {finding.evidence}
                                    </pre>
                                </article>
                            ))
                        )}
                    </div>
                </section>
            </main>

            <section className="proof-strip">
                <article>
                    <h3>What this is</h3>
                    <p>
                        A practical guardrail layer designed to run in pull
                        requests, not a full static analysis replacement.
                    </p>
                </article>
                <article>
                    <h3>Who it fits</h3>
                    <p>
                        Teams with limited AppSec bandwidth that still need
                        strict checks on authz, data boundaries, and risky
                        runtime config changes.
                    </p>
                </article>
                <article>
                    <h3>Private flow</h3>
                    <p>
                        Server-to-server clients can call authenticated scan
                        endpoints with <code>x-api-key</code> and optional
                        OpenRouter key override.
                    </p>
                </article>
            </section>

            <footer className="site-footer">
                <p>ThreatLens · Diff-first security scanning</p>
            </footer>
        </div>
    );
}
