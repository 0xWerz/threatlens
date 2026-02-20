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

const form = document.getElementById("scan-form");
const diffField = document.getElementById("diff");
const findingsEl = document.getElementById("findings");
const summaryEl = document.getElementById("summary");
const scanMetaEl = document.getElementById("scan-meta");
const scanButton = document.getElementById("scan-btn");
const sampleButton = document.getElementById("sample-btn");
const packSelect = document.getElementById("pack");
const failOnSelect = document.getElementById("failOn");

sampleButton.addEventListener("click", () => {
  diffField.value = sampleDiff;
});

async function loadPacks() {
  try {
    const response = await fetch("/api/packs");
    if (!response.ok) {
      throw new Error("Failed to load packs");
    }

    const data = await response.json();
    const packs = data.packs ?? [];

    packSelect.innerHTML = "";

    for (const pack of packs) {
      const option = document.createElement("option");
      option.value = pack.id;
      option.textContent = `${pack.name} (${pack.id})`;
      option.dataset.defaultFailOn = pack.defaultFailOn;
      packSelect.appendChild(option);
    }

    if (packSelect.options.length > 0) {
      const first = packSelect.options[0];
      failOnSelect.value = first.dataset.defaultFailOn || "high";
    }

    packSelect.addEventListener("change", () => {
      const selected = packSelect.options[packSelect.selectedIndex];
      if (!selected) {
        return;
      }
      failOnSelect.value = selected.dataset.defaultFailOn || failOnSelect.value;
    });
  } catch {
    packSelect.innerHTML = '<option value="startup-default">Startup Default</option>';
  }
}

function renderSummary(summary) {
  summaryEl.classList.remove("hidden");

  summaryEl.innerHTML = [
    ["total", summary.total],
    ["high", summary.high],
    ["medium", summary.medium],
    ["low", summary.low],
  ]
    .map(
      ([label, value]) =>
        `<div class="summary-item"><strong>${value}</strong><span>${label}</span></div>`,
    )
    .join("");
}

function renderFindings(findings) {
  findingsEl.innerHTML = "";

  if (!findings.length) {
    findingsEl.innerHTML = '<div class="empty">No findings for this diff and policy pack.</div>';
    return;
  }

  findingsEl.innerHTML = findings
    .map((finding) => {
      return `<article class="finding ${finding.severity}">
          <h4>[${finding.severity.toUpperCase()}] ${escapeHtml(finding.title)}</h4>
          <div class="meta">${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.filePath)}:${finding.line}${finding.source ? ` · ${escapeHtml(finding.source)}` : ""}${typeof finding.confidence === "number" ? ` · conf ${Math.round(finding.confidence * 100)}%` : ""}</div>
          <div class="meta">${escapeHtml(finding.description)}</div>
          <pre class="evidence">${escapeHtml(finding.evidence)}</pre>
        </article>`;
    })
    .join("");
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const diff = diffField.value.trim();
  if (!diff) {
    scanMetaEl.textContent = "Paste a diff first.";
    return;
  }

  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";
  scanMetaEl.textContent = "Running policy checks...";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        diff,
        packId: packSelect.value,
        failOn: failOnSelect.value,
        llm: {
          mode: "off",
        },
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Scan failed");
    }

    renderSummary(data.summary);
    renderFindings(data.findings);

    const blockState = data.shouldBlock ? "block" : "pass";
    scanMetaEl.textContent = `Policy ${data.policy.id} · fail-on ${data.policy.failOn} · ${blockState} · deterministic high=${data.deterministicSummary?.high ?? 0}`;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed";
    scanMetaEl.textContent = message;
    findingsEl.innerHTML = '<div class="empty">Scan failed. Check input and try again.</div>';
    summaryEl.classList.add("hidden");
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Scan diff";
  }
});

loadPacks();
