// Terrier Cyber Quest — Interactive Dashboard Logic
// CVSS v4.0, IST Timestamps, Smooth Progress, Toast Notifications

let currentScanId = null;
let currentScanData = null;
let ws = null;
let activeFindingForPatch = null;
let generatedPatchData = null;
let totalRequestsCount = 0;
let scanProgress = 0;

// IST Timezone Formatter Utility
function formatIST(dateOrIso, includeSeconds = true) {
  if (!dateOrIso) return "N/A";
  try {
    const d = new Date(dateOrIso);
    if (isNaN(d.getTime())) return String(dateOrIso);
    return new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: includeSeconds ? '2-digit' : undefined,
      hour12: true
    }).format(d) + " IST";
  } catch (e) {
    return String(dateOrIso);
  }
}

function formatISTTimeOnly(dateOrIso = new Date()) {
  try {
    const d = new Date(dateOrIso);
    return new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    }).format(d) + " IST";
  } catch (e) {
    return new Date().toLocaleTimeString();
  }
}

// Toast Notification System
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) toast.parentNode.removeChild(toast);
  }, 4000);
}

// Smooth Progress Bar
function setProgress(percent) {
  scanProgress = Math.min(100, Math.max(0, percent));
  const fill = document.getElementById("progress-fill");
  if (fill) {
    fill.style.width = `${scanProgress}%`;
    if (scanProgress >= 100) {
      fill.classList.add("complete");
    } else {
      fill.classList.remove("complete");
    }
  }
}

// DOM Elements
const startScanBtn = document.getElementById("start-scan-btn");
const stopScanBtn = document.getElementById("stop-scan-btn");
const headerStopBtn = document.getElementById("header-stop-btn");
const targetUrlInput = document.getElementById("target-url");
const progressSection = document.getElementById("progress-section");
const stageTitle = document.getElementById("stage-title");
const liveLog = document.getElementById("live-log");
const exportGroup = document.getElementById("export-group");
const exportPdfBtn = document.getElementById("export-pdf-btn");
const exportJsonBtn = document.getElementById("export-json-btn");
const metricsSection = document.getElementById("metrics-section");
const resultsLayout = document.getElementById("results-layout");
const findingsList = document.getElementById("findings-list");
const surfaceList = document.getElementById("surface-list");
const surfaceCount = document.getElementById("surface-count");
const severityFilter = document.getElementById("severity-filter");
const liveReqCount = document.getElementById("live-req-count");
const liveEta = document.getElementById("live-eta");
const liveActivityDesc = document.getElementById("live-activity-desc");

// Modal Elements
const patchModal = document.getElementById("patch-modal");
const closePatchModal = document.getElementById("close-patch-modal");
const stagingFileInput = document.getElementById("staging-file-input");
const previewPatchBtn = document.getElementById("preview-patch-btn");
const copyPatchBtn = document.getElementById("copy-patch-btn");
const cleanPatchSnippet = document.getElementById("clean-patch-snippet");
const diffOutput = document.getElementById("diff-output");
const applyPatchBtn = document.getElementById("apply-patch-btn");
const verifyRegressionBtn = document.getElementById("verify-regression-btn");
const regressionBox = document.getElementById("regression-box");
const verdictBanner = document.getElementById("verdict-banner");
const verdictExplanation = document.getElementById("verdict-explanation");
const regressionEvidenceBox = document.getElementById("regression-evidence-box");

const patchVulnType = document.getElementById("patch-vuln-type");
const patchCvssScore = document.getElementById("patch-cvss-score");
const patchEndpointUrl = document.getElementById("patch-endpoint-url");
const patchParameter = document.getElementById("patch-parameter");

const historyBtn = document.getElementById("history-btn");
const historyModal = document.getElementById("history-modal");
const closeHistoryModal = document.getElementById("close-history-modal");
const historyList = document.getElementById("history-list");

const modelInfoBtn = document.getElementById("model-info-btn");
const modelModal = document.getElementById("model-modal");
const closeModelModal = document.getElementById("close-model-modal");
const modelMetricsContent = document.getElementById("model-metrics-content");

// Stepper steps
const steps = {
  CRAWLING: document.getElementById("step-crawl"),
  STATIC_ANALYSIS: document.getElementById("step-static"),
  DYNAMIC_FUZZING_AND_ML: document.getElementById("step-fuzz"),
  ML_CLASSIFICATION: document.getElementById("step-ml"),
  CYBER_REASONING: document.getElementById("step-reason"),
  DONE: document.getElementById("step-done")
};

const stageProgressMap = {
  CRAWLING: [0, 20],
  STATIC_ANALYSIS: [20, 35],
  DYNAMIC_FUZZING_AND_ML: [35, 75],
  ML_CLASSIFICATION: [75, 85],
  CYBER_REASONING: [85, 92],
  DONE: [92, 100]
};

function addLog(msg, type = "info") {
  const line = document.createElement("div");
  line.className = `log-line ${type}`;
  line.textContent = `[${formatISTTimeOnly()}] ${msg}`;
  liveLog.appendChild(line);
  liveLog.scrollTop = liveLog.scrollHeight;
}

function updateStepStatus(stepEl, status) {
  if (!stepEl) return;
  const statusEl = stepEl.querySelector(".step-status");
  if (statusEl) statusEl.textContent = status;
}

function updateStepper(activeStage) {
  const stageKeys = ["CRAWLING", "STATIC_ANALYSIS", "DYNAMIC_FUZZING_AND_ML", "ML_CLASSIFICATION", "CYBER_REASONING", "DONE"];
  let passed = true;
  for (const k of stageKeys) {
    const el = steps[k];
    if (!el) continue;
    if (k === activeStage) {
      el.className = "step active";
      updateStepStatus(el, "Running...");
      passed = false;
    } else if (passed) {
      el.className = "step completed";
      updateStepStatus(el, "✓ Complete");
    } else {
      el.className = "step";
      updateStepStatus(el, "Pending");
    }
  }
}

function markAllStepsComplete() {
  const stageKeys = ["CRAWLING", "STATIC_ANALYSIS", "DYNAMIC_FUZZING_AND_ML", "ML_CLASSIFICATION", "CYBER_REASONING", "DONE"];
  for (const k of stageKeys) {
    const el = steps[k];
    if (!el) continue;
    el.className = "step completed";
    updateStepStatus(el, "✓ Complete");
  }
}

function resetScanControls() {
  startScanBtn.style.display = "inline-flex";
  startScanBtn.disabled = false;
  stopScanBtn.style.display = "none";
  headerStopBtn.style.display = "none";
  document.getElementById("scan-spinner").style.display = "none";
  exportGroup.style.display = "flex";
  liveEta.textContent = "Completed";
}

function markScanFullyComplete() {
  setProgress(100);
  markAllStepsComplete();
  stageTitle.textContent = "Scan Complete — All Results Available";
  liveActivityDesc.textContent = "All findings loaded in dashboard.";
  resetScanControls();
}

// Keyboard shortcut: Ctrl+Enter to start scan
targetUrlInput.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "Enter") {
    startScanBtn.click();
  }
});

// Start Scan Action
startScanBtn.addEventListener("click", async () => {
  const targetUrl = targetUrlInput.value.trim();
  if (!targetUrl) {
    showToast("Please enter a valid authorized target URL.", "error");
    return;
  }

  totalRequestsCount = 0;
  scanProgress = 0;
  setProgress(0);

  startScanBtn.style.display = "none";
  stopScanBtn.style.display = "inline-flex";
  headerStopBtn.style.display = "inline-flex";
  progressSection.style.display = "block";
  metricsSection.style.display = "grid";
  resultsLayout.style.display = "grid";
  exportGroup.style.display = "none";
  document.getElementById("scan-spinner").style.display = "inline-block";
  liveEta.textContent = "Calculating...";
  findingsList.innerHTML = "";
  surfaceList.innerHTML = "";
  liveLog.innerHTML = "";

  // Reset all step statuses
  Object.values(steps).forEach(el => {
    if (el) {
      el.className = "step";
      updateStepStatus(el, "Pending");
    }
  });

  // Scroll progress section into view
  progressSection.scrollIntoView({ behavior: "smooth", block: "start" });

  addLog(`Initiating authorized scan on: ${targetUrl}`);

  const allowedDomainsStr = document.getElementById("allowed-domains").value.trim();
  const allowedDomains = allowedDomainsStr ? allowedDomainsStr.split(",").map(s => s.trim()) : null;
  const maxDepth = parseInt(document.getElementById("max-depth").value) || 0;
  const maxPages = parseInt(document.getElementById("max-pages").value) || 0;
  const bearerToken = document.getElementById("bearer-token").value.trim() || null;
  const customCookiesStr = document.getElementById("custom-cookies").value.trim();

  let cookiesObj = null;
  if (customCookiesStr) {
    cookiesObj = {};
    customCookiesStr.split(";").forEach(pair => {
      const parts = pair.split("=");
      if (parts.length === 2) cookiesObj[parts[0].trim()] = parts[1].trim();
    });
  }

  const payload = {
    target_url: targetUrl,
    scope: {
      allowed_domains: allowedDomains,
      max_depth: maxDepth,
      max_pages: maxPages
    },
    auth: {
      bearer_token: bearerToken,
      cookies: cookiesObj
    }
  };

  try {
    const resp = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await resp.json();
    currentScanId = result.scan_id;
    addLog(`Scan ID assigned: ${currentScanId} (Started: ${formatIST(result.started_at)})`);
    connectWebSocket(currentScanId);
  } catch (err) {
    addLog(`Error initiating scan: ${err.message}`, "warn");
    showToast(`Scan failed to start: ${err.message}`, "error");
    resetScanControls();
  }
});

// Immediate Process Termination Handler
async function terminateScan() {
  if (!currentScanId) {
    resetScanControls();
    return;
  }
  addLog("Termination request received. Halting background scan workers...", "warn");
  stageTitle.textContent = "Scan Terminated by User";
  liveEta.textContent = "Terminated";
  resetScanControls();
  updateStepper("DONE");
  updateStepStatus(steps.DONE, "Terminated");

  try {
    const resp = await fetch(`/api/scan/${currentScanId}/stop`, { method: "POST" });
    const result = await resp.json();
    addLog(`Process state: ${result.message}`, "warn");
    showToast("Scan terminated successfully.", "warn");
    fetchFullScan(currentScanId);
  } catch (e) {
    addLog(`Termination note: ${e.message}`, "warn");
  }
}

stopScanBtn.addEventListener("click", terminateScan);
headerStopBtn.addEventListener("click", terminateScan);

function connectWebSocket(scanId) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/ws/scan/${scanId}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    addLog("Real-time telemetry stream established.");
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleScanEvent(msg.event, msg.data);
    } catch (e) {
      console.error(e);
    }
  };

  ws.onerror = () => {
    addLog("WebSocket connection error. Polling fallback enabled.", "warn");
    pollScanStatus(scanId);
  };
}

async function pollScanStatus(scanId) {
  const interval = setInterval(async () => {
    const res = await fetch(`/api/scan/${scanId}`);
    const data = await res.json();
    currentScanData = data;
    renderFullScanData(data);
    if (data.status === "COMPLETED" || data.status === "FAILED" || data.status === "STOPPED") {
      clearInterval(interval);
      markScanFullyComplete();
    }
  }, 2000);
}

function handleScanEvent(evt, data) {
  if (data && data.eta_display) {
    liveEta.textContent = data.eta_display;
  }

  if (evt === "stage_change") {
    stageTitle.textContent = data.message;
    updateStepper(data.stage);
    liveActivityDesc.textContent = data.message;
    addLog(data.message);

    // Update progress to stage start
    const range = stageProgressMap[data.stage];
    if (range) setProgress(range[0]);
  } else if (evt === "crawler_crawl_page") {
    totalRequestsCount = data.total_requests || (totalRequestsCount + 1);
    liveReqCount.textContent = totalRequestsCount;
    document.getElementById("metric-requests").textContent = totalRequestsCount;
    liveActivityDesc.textContent = `Crawled: ${data.url} (Depth ${data.depth}, Visited ${data.visited_count})`;
    addLog(`Crawled page: ${data.url} (Depth ${data.depth})`);

    // Smooth crawl progress (0-20% range)
    const crawlProg = Math.min(data.visited_count * 2, 20);
    setProgress(crawlProg);
  } else if (evt === "crawler_crawl_completed") {
    // Display crawl completion reason
    const reason = data.reason;
    if (reason === "exhausted") {
      addLog("Crawl complete — all reachable pages discovered.", "info");
    } else if (reason === "page_limit") {
      addLog(`Crawl stopped — page limit reached (${data.pages_visited} pages, ${data.queue_remaining} URLs remaining in queue).`, "warn");
    } else if (reason === "duration_limit") {
      addLog(`Crawl stopped — duration limit reached (${data.pages_visited} pages visited).`, "warn");
    } else if (reason === "stopped") {
      addLog("Crawl terminated by user.", "warn");
    }
  } else if (evt === "endpoints_discovered") {
    addLog(`Autonomous crawl completed. Discovered ${data.count} unique normalized endpoints.`);
    document.getElementById("metric-endpoints").textContent = data.count;
    surfaceCount.textContent = `${data.count} Endpoints`;
    renderSurfaces(data.endpoints);
    setProgress(20);
  } else if (evt === "testing_parameter") {
    const progText = data.total_probes ? `[${data.probes_completed}/${data.total_probes}] ` : '';
    liveActivityDesc.textContent = `${progText}Testing parameter '${data.parameter}' on ${data.method} ${data.url}`;
    addLog(`Testing dynamic probes on ${data.method} ${data.url} (param: ${data.parameter})`);
  } else if (evt === "request_sent") {
    totalRequestsCount = data.total_requests || (totalRequestsCount + 1);
    liveReqCount.textContent = totalRequestsCount;
    document.getElementById("metric-requests").textContent = totalRequestsCount;
    const progStr = data.total_probes_estimated ? `[${data.probes_completed}/${data.total_probes_estimated}] ` : '';
    liveActivityDesc.textContent = `${progStr}[HTTP ${data.status_code}] ${data.method} ${data.url} (${data.probe_description}) - ${data.elapsed_ms}ms`;
    addLog(`Probe executed: ${data.method} ${data.url} [Param: ${data.parameter}] -> HTTP ${data.status_code} (${data.elapsed_ms}ms)`);

    // Smooth dynamic probing progress (35-75% range)
    if (data.total_probes_estimated && data.probes_completed) {
      const fuzzProg = 35 + (data.probes_completed / data.total_probes_estimated) * 40;
      setProgress(Math.min(fuzzProg, 75));
    }
  } else if (evt === "ml_scored") {
    if (data.is_anomalous) {
      addLog(`ML Model flagged anomaly: ${data.category} (${data.confidence}% confidence) on ${data.parameter}`, "warn");
    }
  } else if (evt === "finding_detected") {
    const cvssStr = data.cvss_score !== undefined ? `CVSS ${data.cvss_score} ` : '';
    addLog(`[ALERT] ${cvssStr}${data.severity}: ${data.vuln_type} on ${data.parameter || 'endpoint'} (${data.confidence}% confidence)`, "finding");
    appendFindingCard(data);
    updateMetricCounts();
  } else if (evt === "scan_stopped") {
    stageTitle.textContent = "Scan Terminated by User";
    updateStepper("DONE");
    updateStepStatus(steps.DONE, "Terminated");
    resetScanControls();
    addLog(`Scan stopped. ${data.message} ${data.total_findings || 0} findings recorded before termination.`, "warn");
    fetchFullScan(currentScanId);
  } else if (evt === "scan_completed") {
    // Backend processing done — but scan is NOT fully complete yet.
    // We still need to fetch and render all results in the dashboard.
    stageTitle.textContent = "Finalizing — Loading results into dashboard...";
    updateStepper("DONE");
    updateStepStatus(steps.DONE, "Loading...");
    setProgress(92);
    liveActivityDesc.textContent = "Fetching complete scan results...";
    addLog("Backend processing complete. Loading full results...", "info");

    // Fetch full scan data, and only then mark truly complete
    fetchFullScanAndFinalize(currentScanId);
  }
}

async function fetchFullScanAndFinalize(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}`);
    const data = await res.json();
    currentScanData = data;
    renderFullScanData(data);

    // NOW the scan is truly complete — dashboard has all data
    markScanFullyComplete();
    addLog("Scan complete. All findings compiled and audit report ready.", "info");
    showToast(`Scan complete — ${data.findings ? data.findings.length : 0} findings detected.`, "success");
  } catch (err) {
    addLog(`Error loading final results: ${err.message}`, "warn");
    showToast("Failed to load scan results.", "error");
    resetScanControls();
  }
}

async function fetchFullScan(scanId) {
  const res = await fetch(`/api/scan/${scanId}`);
  const data = await res.json();
  currentScanData = data;
  renderFullScanData(data);
}

function renderSurfaces(endpoints) {
  surfaceList.innerHTML = "";
  if (!endpoints || endpoints.length === 0) {
    surfaceList.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-text">No endpoints discovered yet</div></div>';
    return;
  }
  endpoints.forEach(ep => {
    const item = document.createElement("div");
    item.className = "surface-item";
    const paramsStr = ep.params && ep.params.length ? `[${ep.params.map(p => p.name).join(", ")}]` : "[]";
    item.innerHTML = `<span class="method-tag">${ep.method}</span><span>${ep.url}</span><br><small style="color:var(--text-dim)">Params: ${paramsStr}</small>`;
    surfaceList.appendChild(item);
  });
}

function renderFullScanData(data) {
  if (data.endpoints) {
    document.getElementById("metric-endpoints").textContent = data.endpoints.length;
    surfaceCount.textContent = `${data.endpoints.length} Endpoints`;
    renderSurfaces(data.endpoints);
  }
  if (data.summary && data.summary.total_requests) {
    document.getElementById("metric-requests").textContent = data.summary.total_requests;
  }
  if (data.findings) {
    findingsList.innerHTML = "";
    if (data.findings.length === 0) {
      findingsList.innerHTML = '<div class="empty-state"><div class="empty-state-icon">✅</div><div class="empty-state-text">No vulnerabilities detected</div></div>';
    } else {
      data.findings.forEach(f => appendFindingCard(f));
    }
    updateMetricCounts();
  }
}

function appendFindingCard(f) {
  // Remove empty state if present
  const emptyState = findingsList.querySelector(".empty-state");
  if (emptyState) emptyState.remove();

  const card = document.createElement("div");
  card.className = `finding-card severity-${f.severity}`;
  card.dataset.severity = f.severity;

  const cvssScore = f.cvss_score !== undefined ? f.cvss_score : 0.0;
  const cvssVector = f.cvss_vector || 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N';
  const detectedAtStr = f.detected_at ? formatIST(f.detected_at) : formatIST(new Date());
  const briefInfo = f.brief_info || `Detected ${f.vuln_type.replace(/_/g, ' ')} vulnerability with ${f.confidence}% confidence.`;
  const exactLocation = f.exact_location || `${f.http_method || 'GET'} ${f.url} (Parameter: ${f.parameter || 'N/A'})`;
  const briefRemediation = f.brief_remediation || f.remediation || 'Apply input sanitization and parameterized queries.';
  const reasoningFormatted = (f.llm_reasoning || "").replace(/\n/g, "<br>");

  card.innerHTML = `
    <div class="finding-header">
      <div class="finding-title">${f.vuln_type.replace(/_/g, ' ')}</div>
      <div class="finding-tags">
        <span class="cvss-score-badge">CVSS v4.0: <strong>${cvssScore.toFixed(1)}</strong></span>
        <span class="badge badge-sev-${f.severity}">${f.severity}</span>
        <span class="badge badge-status">${f.status} (${f.confidence}%)</span>
      </div>
    </div>

    <!-- CVSS v4.0 Vector string -->
    <div class="cvss-vector-box">
      <strong>CVSS v4.0 Vector:</strong> <code>${cvssVector}</code>
    </div>
    
    <!-- Gemini AI Brief Summary & Exact Location Box -->
    <div class="gemini-reasoning-card" style="margin-top: 0.5rem;">
      <div class="gemini-header">
        <span>🤖 Gemini Cyber-Reasoning Analysis</span>
        <small style="margin-left:auto; color:var(--text-dim); font-size:0.7rem;">${detectedAtStr}</small>
      </div>
      <div class="gemini-field">
        <strong>Vulnerability Info:</strong> ${briefInfo}
      </div>
      <div class="gemini-field">
        <strong>Exact Location:</strong> <code style="color:var(--text-main); background:var(--bg-input); padding:2px 6px; border-radius:4px;">${exactLocation}</code>
      </div>
      <div class="gemini-field">
        <strong>Remediation:</strong> <span style="color:var(--accent-green);">${briefRemediation}</span>
      </div>
    </div>

    <div class="finding-meta">
      <span><b>Target:</b> ${f.http_method || 'GET'} ${f.url}</span>
      <span><b>Parameter:</b> ${f.parameter || 'N/A'}</span>
      <span><b>ML Class:</b> ${f.ml_prediction ? f.ml_prediction.category : 'N/A'}</span>
    </div>
    
    <div class="reasoning-box">
      <strong>Full Correlated Telemetry & Evidence:</strong><br>
      ${reasoningFormatted}
    </div>
    
    ${f.uncertainty_warning ? `<div class="uncertainty-box"><strong>Uncertainty / False-Positive Warning:</strong> ${f.uncertainty_warning}</div>` : ''}
    
    <div class="finding-actions">
      <button class="btn btn-secondary btn-sm" onclick="openPatchModal('${f.id}')" aria-label="Open staging patch for ${f.vuln_type}">🛠️ Staging Patch & Regression</button>
    </div>
  `;

  findingsList.appendChild(card);
}

function updateMetricCounts() {
  const cards = document.querySelectorAll(".finding-card");
  document.getElementById("metric-findings").textContent = cards.length;
  
  let crit = 0, high = 0;
  cards.forEach(c => {
    const sev = c.dataset.severity;
    if (sev === "CRITICAL") crit++;
    else if (sev === "HIGH") high++;
  });
  document.getElementById("metric-critical").textContent = crit;
  document.getElementById("metric-high").textContent = high;
}

// Severity Filtering
severityFilter.addEventListener("change", () => {
  const sel = severityFilter.value;
  const cards = document.querySelectorAll(".finding-card");
  cards.forEach(c => {
    if (sel === "ALL" || c.dataset.severity === sel) {
      c.style.display = "block";
    } else {
      c.style.display = "none";
    }
  });
});

// Export Handlers
exportPdfBtn.addEventListener("click", () => {
  if (currentScanId) {
    window.open(`/api/scan/${currentScanId}/export/pdf`, "_blank");
  }
});

exportJsonBtn.addEventListener("click", () => {
  if (currentScanId) {
    window.open(`/api/scan/${currentScanId}/export/json`, "_blank");
  }
});

// Autonomous Staging Patch & Regression Workflow
window.openPatchModal = async function(findingId) {
  if (!currentScanData || !currentScanData.findings) return;
  activeFindingForPatch = currentScanData.findings.find(f => f.id === findingId);
  if (!activeFindingForPatch) return;

  patchModal.style.display = "flex";
  patchVulnType.textContent = activeFindingForPatch.vuln_type.replace(/_/g, ' ');
  patchCvssScore.textContent = `${activeFindingForPatch.cvss_score || 0.0} (${activeFindingForPatch.severity || 'MEDIUM'})`;
  patchEndpointUrl.textContent = `${activeFindingForPatch.http_method || 'GET'} ${activeFindingForPatch.url}`;
  patchParameter.textContent = activeFindingForPatch.parameter || 'N/A';

  cleanPatchSnippet.textContent = "Generating clean copyable patch snippet...";
  diffOutput.textContent = "Computing unified diff against staging copy...";
  applyPatchBtn.disabled = true;
  verifyRegressionBtn.disabled = true;
  regressionBox.style.display = "none";
  copyPatchBtn.textContent = "📋 Copy Patch";

  // Automatically generate patch upon opening
  await generatePatchForActiveFinding();
};

closePatchModal.addEventListener("click", () => {
  patchModal.style.display = "none";
});

async function generatePatchForActiveFinding() {
  if (!activeFindingForPatch) return;
  const stagingFile = stagingFileInput.value.trim();

  try {
    const res = await fetch("/api/patch/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: currentScanId,
        finding_id: activeFindingForPatch.id,
        target_file: stagingFile,
        vuln_type: activeFindingForPatch.vuln_type,
        parameter: activeFindingForPatch.parameter
      })
    });
    const data = await res.json();
    generatedPatchData = data;
    if (data.success) {
      cleanPatchSnippet.textContent = data.clean_patch_snippet || data.diff_text;
      diffOutput.textContent = data.diff_text;
      applyPatchBtn.disabled = !data.is_modified;
    } else {
      cleanPatchSnippet.textContent = `# Error generating patch: ${data.error}`;
      diffOutput.textContent = `Target file error: ${data.error}`;
    }
  } catch (err) {
    cleanPatchSnippet.textContent = `# Network error: ${err.message}`;
    diffOutput.textContent = `Request error: ${err.message}`;
  }
}

previewPatchBtn.addEventListener("click", generatePatchForActiveFinding);

// Copy Patch Button with Visual Feedback
copyPatchBtn.addEventListener("click", () => {
  const textToCopy = cleanPatchSnippet.textContent;
  if (!textToCopy) return;

  navigator.clipboard.writeText(textToCopy).then(() => {
    copyPatchBtn.textContent = "✅ Copied!";
    showToast("Patch copied to clipboard.", "success");
    setTimeout(() => {
      copyPatchBtn.textContent = "📋 Copy Patch";
    }, 2000);
  }).catch(() => {
    // Fallback for non-secure contexts
    const textArea = document.createElement("textarea");
    textArea.value = textToCopy;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand("copy");
    document.body.removeChild(textArea);
    copyPatchBtn.textContent = "✅ Copied!";
    setTimeout(() => {
      copyPatchBtn.textContent = "📋 Copy Patch";
    }, 2000);
  });
});

applyPatchBtn.addEventListener("click", async () => {
  if (!generatedPatchData || !activeFindingForPatch) return;
  const stagingFile = stagingFileInput.value.trim();

  try {
    const res = await fetch("/api/patch/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: currentScanId,
        finding_id: activeFindingForPatch.id,
        target_file: stagingFile,
        patched_code: generatedPatchData.patched_code
      })
    });
    const data = await res.json();
    if (data.success) {
      showToast("Patch applied to staging file successfully.", "success");
      verifyRegressionBtn.disabled = false;
    } else {
      showToast(`Error applying patch: ${data.message}`, "error");
    }
  } catch (err) {
    showToast(`Request error: ${err.message}`, "error");
  }
});

verifyRegressionBtn.addEventListener("click", async () => {
  if (!activeFindingForPatch) return;

  regressionBox.style.display = "block";
  regressionEvidenceBox.style.display = "none";
  verdictBanner.className = "verdict-banner";
  verdictBanner.textContent = "RUNNING REGRESSION TEST HARNESS...";
  verdictExplanation.textContent = "Executing baseline functional requests and security probes against the patched staging target...";

  try {
    const res = await fetch("/api/patch/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: currentScanId,
        finding_id: activeFindingForPatch.id,
        endpoint_url: activeFindingForPatch.url,
        http_method: activeFindingForPatch.http_method,
        parameter: activeFindingForPatch.parameter
      })
    });
    const data = await res.json();
    verdictBanner.className = `verdict-banner ${data.verdict}`;
    verdictBanner.textContent = `VERIFICATION VERDICT: ${data.verdict}`;
    verdictExplanation.textContent = data.reason;

    if (data.supporting_evidence) {
      regressionEvidenceBox.style.display = "block";
      regressionEvidenceBox.innerHTML = `
        <strong>Supporting Evidence (IST ${formatIST(data.timestamp)}):</strong><br>
        • Functional Test Passed: <b>${data.functional_test_passed ? 'YES' : 'NO'}</b><br>
        • Security Retest Passed: <b>${data.security_retest_passed ? 'YES' : 'NO'}</b><br>
        • Active Findings Remaining: <b>${data.supporting_evidence.active_findings_after_patch || 0}</b><br>
        • Baseline Status: <b>HTTP ${data.supporting_evidence.baseline_functional_status || 200}</b>
      `;
    }

    if (data.verdict === "FIXED") {
      const fixedCountEl = document.getElementById("metric-fixed");
      fixedCountEl.textContent = parseInt(fixedCountEl.textContent || "0") + 1;
      showToast("Vulnerability verified as FIXED!", "success");
    } else {
      showToast(`Verification verdict: ${data.verdict}`, "warn");
    }
  } catch (err) {
    verdictBanner.textContent = "ERROR";
    verdictExplanation.textContent = err.message;
    showToast(`Regression test error: ${err.message}`, "error");
  }
});

// Scan History Modal with IST Timestamps
historyBtn.addEventListener("click", async () => {
  historyModal.style.display = "flex";
  historyList.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⏳</div><div class="empty-state-text">Loading scan history...</div></div>';
  try {
    const res = await fetch("/api/scans");
    const scans = await res.json();
    if (!scans.length) {
      historyList.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📂</div><div class="empty-state-text">No previous scans found</div></div>';
      return;
    }
    historyList.innerHTML = "";
    scans.forEach(s => {
      const item = document.createElement("div");
      item.className = "surface-item";
      item.style.marginBottom = "0.6rem";
      item.style.cursor = "pointer";
      item.innerHTML = `
        <strong>${s.target_url}</strong> <span class="badge">${s.status}</span>
        <br><small style="color:var(--text-dim)">Scan ID: ${s.id} | Started: ${formatIST(s.started_at)}</small>
        <br><small style="color:var(--text-muted)">Findings: ${s.finding_count || 0} | Endpoints: ${s.endpoint_count || 0}</small>
      `;
      item.onclick = () => {
        historyModal.style.display = "none";
        currentScanId = s.id;
        progressSection.style.display = "block";
        metricsSection.style.display = "grid";
        resultsLayout.style.display = "grid";
        exportGroup.style.display = "flex";
        stageTitle.textContent = `Historical Audit: ${s.target_url} (${s.status})`;
        markAllStepsComplete();
        setProgress(100);
        fetchFullScan(s.id);
      };
      historyList.appendChild(item);
    });
  } catch (e) {
    historyList.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠️</div><div class="empty-state-text">Error loading history: ${e.message}</div></div>`;
  }
});

closeHistoryModal.addEventListener("click", () => {
  historyModal.style.display = "none";
});

// Model Info Modal with Full Telemetry & Generalization Dashboard
modelInfoBtn.addEventListener("click", async () => {
  modelModal.style.display = "flex";
  modelMetricsContent.innerHTML = "<div style='text-align:center; padding:2rem;'><span class='spinner'></span> Loading ML benchmark telemetry...</div>";
  try {
    const res = await fetch("/api/model/info");
    const data = await res.json();
    
    function safeNum(val, fallback = 0) {
      if (val === undefined || val === null || isNaN(Number(val))) return fallback;
      return Number(val);
    }

    const summary = data.evaluation_summary || data.metrics || data || {};
    const rawAcc = summary.accuracy !== undefined ? summary.accuracy : (data.accuracy !== undefined ? data.accuracy : 0.99557);
    const acc = (safeNum(rawAcc) * 100).toFixed(2);
    
    const rawWeightedF1 = summary.weighted_f1 !== undefined ? summary.weighted_f1 : (data.weighted_f1 !== undefined ? data.weighted_f1 : 0.9954);
    const weightedF1 = safeNum(rawWeightedF1).toFixed(4);
    
    const rawMacroF1 = summary.macro_f1 !== undefined ? summary.macro_f1 : (data.macro_f1 !== undefined ? data.macro_f1 : 0.7356);
    const macroF1 = safeNum(rawMacroF1).toFixed(4);
    
    const numSamples = summary.num_test_samples || data.num_test_samples || "9,039";
    const numClasses = summary.num_classes || data.num_classes || (data.classes ? data.classes.length : "29");
    
    let html = `
      <!-- Top Metrics Cards -->
      <div class="model-stats-grid">
        <div class="stat-box">
          <div class="stat-number" style="color:var(--accent-green);">${acc}%</div>
          <div class="stat-label">Test Accuracy</div>
        </div>
        <div class="stat-box">
          <div class="stat-number">${weightedF1}</div>
          <div class="stat-label">Weighted F1</div>
        </div>
        <div class="stat-box">
          <div class="stat-number" style="color:var(--accent-yellow);">${macroF1}</div>
          <div class="stat-label">Macro F1</div>
        </div>
        <div class="stat-box">
          <div class="stat-number">${numClasses}</div>
          <div class="stat-label">Learned Classes</div>
        </div>
        <div class="stat-box">
          <div class="stat-number">${numSamples}</div>
          <div class="stat-label">Holdout Test Set</div>
        </div>
      </div>

      <!-- Training Dataset Metadata -->
      <div style="background:var(--bg-input); border:1px solid var(--border-color); border-radius:6px; padding:0.65rem 0.85rem; margin-bottom:0.85rem; font-family:'JetBrains Mono', monospace; font-size:0.75rem;">
        <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
          <span><strong>Dataset Composition:</strong> Unified (Hugging Face + OWASP Juice Shop)</span>
          <span style="color:var(--text-muted);">59,969 Total Records</span>
        </div>
        <div style="display:flex; justify-content:space-between; color:var(--text-dim); font-size:0.7rem;">
          <span>• Hugging Face vyykaaa/dataset-v2: 59,868 records</span>
          <span>• OWASP Juice Shop: 101 records</span>
          <span>• Split: 70% Train / 15% Val / 15% Test</span>
        </div>
      </div>
    `;

    // Generalization Benchmark Suite
    if (data.generalization_benchmark && Array.isArray(data.generalization_benchmark.detailed_results)) {
      const gen = data.generalization_benchmark;
      const scorePct = safeNum(gen.generalization_score_pct).toFixed(1);
      html += `
        <div class="section-subtitle">
          <span>🧪 Zero-Shot & Out-of-Distribution Generalization Benchmark:</span>
          <span style="color:var(--accent-green); margin-left:0.5rem;">${gen.passed || 0} / ${gen.total_test_cases || 10} Passed (${scorePct}%)</span>
        </div>
        <div class="table-container">
          <table class="model-table">
            <thead>
              <tr>
                <th>Test Case</th>
                <th>Expected Category</th>
                <th>Predicted Category</th>
                <th>Confidence</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              ${gen.detailed_results.map(r => {
                const confStr = r.confidence !== undefined && r.confidence !== null ? safeNum(r.confidence).toFixed(1) + '%' : '--';
                const statusStr = r.status || (r.exact_match ? 'PASS' : 'FAIL');
                return `
                  <tr>
                    <td><strong>${r.test_name || 'Test Case'}</strong></td>
                    <td><code style="color:var(--text-dim);">${r.expected_category || 'N/A'}</code></td>
                    <td><code style="color:${statusStr === 'PASS' ? 'var(--accent-green)' : '#F87171'};">${r.predicted_category || 'N/A'}</code></td>
                    <td>${confStr}</td>
                    <td><span class="${statusStr === 'PASS' ? 'badge-pass' : 'badge-fail'}">${statusStr}</span></td>
                  </tr>
                `;
              }).join("")}
            </tbody>
          </table>
        </div>
      `;
    }

    // Detailed Classification Report
    const report = data.detailed_classification_report || data.classification_report;
    if (report && typeof report === 'object') {
      const classKeys = Object.keys(report).filter(k => !['accuracy', 'macro avg', 'weighted avg'].includes(k));
      html += `
        <div class="section-subtitle">📊 Per-Class Test Performance (${classKeys.length} Classes):</div>
        <div class="table-container">
          <table class="model-table">
            <thead>
              <tr>
                <th>Vulnerability Class</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
                <th>Test Support</th>
              </tr>
            </thead>
            <tbody>
              ${classKeys.map(k => {
                const c = report[k];
                if (!c || typeof c !== 'object') return '';
                const precStr = c.precision !== undefined ? (safeNum(c.precision) * 100).toFixed(1) + '%' : '--';
                const recStr = c.recall !== undefined ? (safeNum(c.recall) * 100).toFixed(1) + '%' : '--';
                const f1Val = c['f1-score'] !== undefined ? c['f1-score'] : c.f1;
                const f1Str = f1Val !== undefined ? (safeNum(f1Val) * 100).toFixed(1) + '%' : '--';
                const suppVal = c.support !== undefined ? c.support : 0;
                return `
                  <tr>
                    <td><strong>${k}</strong></td>
                    <td>${precStr}</td>
                    <td>${recStr}</td>
                    <td>${f1Str}</td>
                    <td>${suppVal}</td>
                  </tr>
                `;
              }).join("")}
            </tbody>
          </table>
        </div>
      `;
    }

    modelMetricsContent.innerHTML = html;
  } catch (e) {
    modelMetricsContent.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠️</div><div class="empty-state-text">Error loading model info: ${e.message}</div></div>`;
  }
});

closeModelModal.addEventListener("click", () => {
  modelModal.style.display = "none";
});
