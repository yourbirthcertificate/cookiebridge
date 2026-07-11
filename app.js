import {
  MAX_BUNDLE_BYTES,
  analyzeImport,
  clearCookieValues,
  compareCookieRecords,
  countMissingCookieIdentities,
  cookieIdentity,
  cookieMatchesDomains,
  cookieToSetDetails,
  createPayload,
  decryptBundle,
  encryptBundle,
  formatImportFailure,
  markAmbiguousDuplicates,
  parseDomainList,
  sanitizeCookie,
  setCookieWithConflictPolicy,
  summarizeCookies,
} from "./lib/bridge-core.js";

const REQUIRED_ORIGINS = ["http://*/*", "https://*/*"];
const THEME_STORAGE_KEY = "cookie-bridge-theme";
let inspectedState = null;
let operationActive = false;

function initThemeToggle() {
  const toggle = document.getElementById("theme-toggle");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)");

  function storedTheme() {
    const value = localStorage.getItem(THEME_STORAGE_KEY);
    return value === "light" || value === "dark" ? value : null;
  }

  function effectiveTheme() {
    return storedTheme() ?? (prefersDark.matches ? "dark" : "light");
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    toggle.textContent = theme === "dark" ? "light mode" : "dark mode";
    toggle.setAttribute("aria-pressed", String(theme === "dark"));
  }

  toggle.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    localStorage.setItem(THEME_STORAGE_KEY, next);
    applyTheme(next);
  });
  prefersDark.addEventListener("change", () => {
    if (!storedTheme()) applyTheme(effectiveTheme());
  });
  applyTheme(effectiveTheme());
}

const elements = Object.fromEntries(
  [
    "domain-field",
    "export-domains",
    "broad-confirmation",
    "confirm-broad",
    "broad-warning-text",
    "all-confirmation",
    "confirm-all",
    "export-passphrase",
    "export-passphrase-confirm",
    "show-export-passphrase",
    "generate-passphrase",
    "export-button",
    "export-progress",
    "export-status",
    "import-file",
    "import-passphrase",
    "show-import-passphrase",
    "inspect-button",
    "inspection",
    "import-button",
    "import-progress",
    "import-status",
  ].map((id) => [id, document.getElementById(id)]),
);

function selectedValue(name) {
  return document.querySelector(`input[name="${name}"]:checked`)?.value;
}

function setStatus(element, type, message) {
  element.className = `status${type ? ` ${type}` : ""}`;
  element.textContent = message;
}

function setBusy(button, busy, busyLabel, idleLabel) {
  button.disabled = busy;
  button.textContent = busy ? busyLabel : idleLabel;
}

function setExportInputsLocked(locked) {
  const controls = document.querySelectorAll(
    '#export-card input, #export-card textarea, #generate-passphrase',
  );
  for (const control of controls) control.disabled = locked;
}

function setImportInputsLocked(locked) {
  const controls = document.querySelectorAll(
    '#import-card input:not(#import-button)',
  );
  for (const control of controls) control.disabled = locked;
}

function beginOperation(statusElement) {
  if (operationActive) {
    setStatus(statusElement, "warning", "Another Cookie Bridge operation is already running in this tab.");
    return false;
  }
  operationActive = true;
  setExportInputsLocked(true);
  setImportInputsLocked(true);
  elements["export-button"].disabled = true;
  elements["inspect-button"].disabled = true;
  elements["import-button"].disabled = true;
  return true;
}

function endOperation() {
  operationActive = false;
  setExportInputsLocked(false);
  setImportInputsLocked(false);
  elements["export-button"].disabled = false;
  elements["inspect-button"].disabled = false;
  elements["import-button"].disabled =
    !inspectedState || inspectedState.analysis.ready.length === 0;
}

async function ensureHostAccess() {
  const permissions = { origins: REQUIRED_ORIGINS };
  // Keep request() as the first asynchronous browser call in a click handler.
  // A preceding await can consume Chromium's transient user activation.
  const granted = await chrome.permissions.request(permissions);
  if (!granted) {
    throw new Error("Cookie access was not granted. No browser data was read or changed.");
  }
}

async function acquireCrossTabLock() {
  if (!navigator.locks?.request) {
    return async () => {};
  }
  let releaseHold;
  let signalAcquired;
  const hold = new Promise((resolve) => {
    releaseHold = resolve;
  });
  const acquired = new Promise((resolve) => {
    signalAcquired = resolve;
  });
  const request = navigator.locks.request("local-cookie-bridge-operation", async () => {
    signalAcquired();
    await hold;
  });
  await Promise.race([
    acquired,
    request.then(() => {
      throw new Error("The cross-tab operation lock closed before it was acquired.");
    }),
  ]);
  let released = false;
  return async () => {
    if (released) return;
    released = true;
    releaseHold();
    try {
      await request;
    } catch {
      // The browser releases the lock automatically if a page closes.
    }
  };
}

async function getAllCookiesIncludingPartitions() {
  try {
    return {
      cookies: await chrome.cookies.getAll({ partitionKey: {} }),
      supportsPartitioned: true,
    };
  } catch {
    return {
      cookies: await chrome.cookies.getAll({}),
      supportsPartitioned: false,
    };
  }
}

async function getCurrentCookiesForIdentity(cookie) {
  // Omitting partitionKey selects unpartitioned cookies; partitioned records use their exact key.
  const details = {
    domain: cookie.domain.replace(/^\./u, ""),
    name: cookie.name,
    path: cookie.path,
  };
  if (cookie.partitionKey?.topLevelSite) {
    details.partitionKey = { ...cookie.partitionKey };
  }
  return chrome.cookies.getAll(details);
}

function generatePassphrase() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function filenameForNow() {
  const stamp = new Date().toISOString().replace(/[-:]/gu, "").replace(/T/u, "-").slice(0, 13);
  return `cookie-bridge-${stamp}.vcookies`;
}

function downloadText(serialized) {
  const blob = new Blob([serialized], { type: "application/json" });
  if (blob.size > MAX_BUNDLE_BYTES) {
    throw new Error("The encrypted bundle exceeds the 50 MB safety limit. Export fewer domains.");
  }
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filenameForNow();
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function toggleExportScope() {
  const all = selectedValue("export-scope") === "all";
  elements["domain-field"].classList.toggle("hidden", all);
  elements["all-confirmation"].classList.toggle("hidden", !all);
  if (all) {
    elements["broad-confirmation"].classList.add("hidden");
    elements["confirm-broad"].checked = false;
  }
}

function resetBroadConfirmation() {
  elements["broad-confirmation"].classList.add("hidden");
  elements["confirm-broad"].checked = false;
}

function validateExportInputs() {
  const scopeType = selectedValue("export-scope");
  let domains = [];
  if (scopeType === "all") {
    if (!elements["confirm-all"].checked) {
      throw new Error("Confirm the all-domain warning before exporting the full cookie jar.");
    }
  } else {
    const parsed = parseDomainList(elements["export-domains"].value);
    if (parsed.invalid.length > 0) {
      throw new Error(`These domain entries are invalid: ${parsed.invalid.slice(0, 3).join(", ")}`);
    }
    if (parsed.domains.length === 0) {
      throw new Error("Enter at least one domain, or select every accessible domain.");
    }
    domains = parsed.domains;
  }

  const passphrase = elements["export-passphrase"].value;
  if (passphrase.length < 12) {
    throw new Error("Use a bundle passphrase of at least 12 characters.");
  }
  if (passphrase !== elements["export-passphrase-confirm"].value) {
    throw new Error("The export passphrases do not match.");
  }
  return { scopeType, domains, passphrase };
}

function exposedDuplicateCount(cookies) {
  const counts = new Map();
  for (const cookie of cookies) {
    const key = cookieIdentity(cookie);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  let total = 0;
  for (const count of counts.values()) {
    if (count > 1) total += count;
  }
  return total;
}

function applyOriginHeuristics(cookies) {
  return cookies.map((cookie) => ({
    ...cookie,
    sourceScheme: "https",
    sourcePort: 443,
    originConfidence: cookie.secure ? "derived" : "unknown",
  }));
}

async function handleExport() {
  setStatus(elements["export-status"], "", "");
  if (!beginOperation(elements["export-status"])) return;
  let inputs;
  let releaseCrossTabLock = null;
  try {
    inputs = validateExportInputs();
    setBusy(elements["export-button"], true, "Reading cookies…", "Create encrypted bundle");
    elements["export-progress"].classList.remove("hidden");
    elements["export-progress"].removeAttribute("value");
    await ensureHostAccess();
    releaseCrossTabLock = await acquireCrossTabLock();

    const snapshot = await getAllCookiesIncludingPartitions();
    let cookies = snapshot.cookies;
    if (inputs.scopeType === "domains") {
      cookies = cookies.filter((cookie) => cookieMatchesDomains(cookie, inputs.domains));
    }
    if (cookies.length === 0) {
      throw new Error("No matching cookies were found in this regular browser profile.");
    }
    const rawSummary = summarizeCookies(cookies);
    if (inputs.scopeType === "domains" && !elements["confirm-broad"].checked) {
      elements["broad-warning-text"].textContent =
        `This scope matches ${rawSummary.total.toLocaleString()} cookies across ${rawSummary.domains.toLocaleString()} distinct cookie domains. Confirm this exact match before exporting.`;
      elements["broad-confirmation"].classList.remove("hidden");
      const error = new Error("Review and confirm the selected-domain match, then create the bundle again.");
      error.name = "ConfirmationRequired";
      throw error;
    }

    const duplicateCount = exposedDuplicateCount(cookies);
    cookies = markAmbiguousDuplicates(applyOriginHeuristics(cookies)).map(sanitizeCookie);
    const payload = createPayload(
      cookies,
      { type: inputs.scopeType, domains: inputs.domains },
      {
        partitionWildcardSupported: snapshot.supportsPartitioned,
        originBindingNote: "Secure cookies use HTTPS/443. Non-Secure cookies use an HTTPS/443 heuristic because the extension API does not expose source scheme or port.",
      },
    );
    setBusy(elements["export-button"], true, "Encrypting bundle…", "Create encrypted bundle");
    const serialized = await encryptBundle(payload, inputs.passphrase);
    downloadText(serialized);

    const summary = summarizeCookies(cookies);
    const caveats = [];
    if (!snapshot.supportsPartitioned) caveats.push("partitioned-cookie enumeration was unavailable");
    if (duplicateCount > 0) caveats.push(`${duplicateCount} origin-bound duplicate records were marked non-portable`);
    if (summary.originHeuristic > 0) caveats.push(`${summary.originHeuristic} non-Secure cookies use an HTTPS origin heuristic`);
    const suffix = caveats.length > 0 ? ` Caveat: ${caveats.join("; ")}.` : "";
    setStatus(
      elements["export-status"],
      caveats.length > 0 ? "warning" : "success",
      `Encrypted ${summary.total.toLocaleString()} cookies across ${summary.domains.toLocaleString()} domains.${suffix}`,
    );
  } catch (error) {
    setStatus(
      elements["export-status"],
      error.name === "ConfirmationRequired" ? "warning" : "error",
      error.message || "Export failed.",
    );
  } finally {
    if (releaseCrossTabLock) await releaseCrossTabLock();
    elements["export-progress"].classList.add("hidden");
    elements["export-progress"].value = 0;
    setBusy(elements["export-button"], false, "", "Create encrypted bundle");
    endOperation();
  }
}

function clearInspection() {
  const previousState = inspectedState;
  inspectedState = null;
  clearCookieValues(previousState?.payload?.cookies);
  elements.inspection.replaceChildren();
  elements.inspection.classList.add("hidden");
  elements["import-button"].disabled = true;
  setStatus(elements["import-status"], "", "");
}

function addMetric(container, value, label) {
  const metric = document.createElement("div");
  metric.className = "metric";
  const strong = document.createElement("strong");
  strong.textContent = Number(value).toLocaleString();
  const span = document.createElement("span");
  span.textContent = label;
  metric.append(strong, span);
  container.append(metric);
}

function renderInspection(payload, analysis) {
  const container = elements.inspection;
  container.replaceChildren();
  addMetric(container, analysis.ready.length, "ready to import");
  addMetric(container, analysis.conflicts.length, "existing conflicts skipped");
  addMetric(container, analysis.expired.length, "expired skipped");
  addMetric(container, analysis.invalid.length, "invalid/non-portable");
  addMetric(container, analysis.unsupportedPartitioned.length, "partitioned unsupported");
  addMetric(container, analysis.ambiguousTarget.length, "ambiguous target skipped");
  addMetric(container, payload.cookies.length, "bundle total");
  const note = document.createElement("p");
  note.className = "inspection-note";
  const exported = new Date(payload.exportedAt).toLocaleString();
  const heuristics = summarizeCookies(payload.cookies).originHeuristic;
  note.textContent = `Exported ${exported}. ${heuristics.toLocaleString()} non-Secure cookies use an origin heuristic and may not survive origin binding.`;
  container.append(note);
  container.classList.remove("hidden");
}

async function handleInspect() {
  if (!beginOperation(elements["import-status"])) return;
  let releaseCrossTabLock = null;
  try {
    clearInspection();
    const file = elements["import-file"].files?.[0];
    const passphrase = elements["import-passphrase"].value;
    if (!file) throw new Error("Select an encrypted .vcookies bundle.");
    if (file.size <= 0 || file.size > MAX_BUNDLE_BYTES) {
      throw new Error("The selected bundle is empty or exceeds the 50 MB safety limit.");
    }
    if (passphrase.length < 12) throw new Error("Enter the bundle passphrase.");

    setBusy(elements["inspect-button"], true, "Inspecting…", "Decrypt and inspect");
    await ensureHostAccess();
    releaseCrossTabLock = await acquireCrossTabLock();
    const payload = await decryptBundle(await file.text(), passphrase);
    const targetSnapshot = await getAllCookiesIncludingPartitions();
    const conflictMode = selectedValue("conflict-mode");
    const analysis = analyzeImport(payload.cookies, targetSnapshot.cookies, {
      conflictMode,
      supportsPartitioned: targetSnapshot.supportsPartitioned,
    });
    inspectedState = { payload, analysis, conflictMode };
    renderInspection(payload, analysis);
    elements["import-button"].disabled = analysis.ready.length === 0;
    setStatus(
      elements["import-status"],
      analysis.ready.length > 0 ? "success" : "warning",
      analysis.ready.length > 0
        ? "Inspection complete. No cookies have been changed yet."
        : "Nothing is ready to import under the selected conflict policy.",
    );
  } catch (error) {
    clearInspection();
    setStatus(elements["import-status"], "error", error.message || "Inspection failed.");
  } finally {
    if (releaseCrossTabLock) await releaseCrossTabLock();
    setBusy(elements["inspect-button"], false, "", "Decrypt and inspect");
    endOperation();
  }
}

function sanitizedFailureReason(error, cookie) {
  let message = String(error?.message || "Browser rejected the cookie.");
  if (cookie.name) message = message.split(cookie.name).join("[cookie]");
  if (cookie.value) message = message.split(cookie.value).join("[value]");
  return message.slice(0, 180);
}

function groupFailures(failures) {
  const grouped = new Map();
  for (const failure of failures) {
    const domain = failure.cookie.domain.replace(/^\./u, "");
    const key = `${domain}\n${failure.reason}`;
    const current = grouped.get(key) ?? { domain, reason: failure.reason, count: 0 };
    current.count += 1;
    grouped.set(key, current);
  }
  return [...grouped.values()];
}

async function handleImport() {
  if (!inspectedState || inspectedState.conflictMode !== selectedValue("conflict-mode")) {
    setStatus(elements["import-status"], "error", "Inspect the bundle again before importing.");
    return;
  }

  const failures = [];
  const written = [];
  let writeCount = 0;
  let adjustedExpirations = 0;
  let destinationRemovals = 0;
  let lateConflicts = 0;
  let releaseCrossTabLock = null;
  if (!beginOperation(elements["import-status"])) return;
  try {
    setBusy(elements["import-button"], true, "Importing sequentially…", "Import inspected cookies");
    await ensureHostAccess();
    releaseCrossTabLock = await acquireCrossTabLock();
    const targetSnapshot = await getAllCookiesIncludingPartitions();
    const refreshedAnalysis = analyzeImport(inspectedState.payload.cookies, targetSnapshot.cookies, {
      conflictMode: inspectedState.conflictMode,
      supportsPartitioned: targetSnapshot.supportsPartitioned,
    });
    inspectedState.analysis = refreshedAnalysis;
    renderInspection(inspectedState.payload, refreshedAnalysis);
    const ready = refreshedAnalysis.ready.map(sanitizeCookie);
    if (ready.length === 0) {
      setStatus(
        elements["import-status"],
        "warning",
        "The destination changed after inspection; no cookies remain ready under this conflict policy.",
      );
      return;
    }
    elements["import-progress"].classList.remove("hidden");
    elements["import-progress"].max = ready.length;
    elements["import-progress"].value = 0;

    for (let index = 0; index < ready.length; index += 1) {
      const cookie = ready[index];
      try {
        const outcome = await setCookieWithConflictPolicy(cookie, inspectedState.conflictMode, {
          getCurrentCookies: getCurrentCookiesForIdentity,
          setCookie: (candidate) => chrome.cookies.set(cookieToSetDetails(candidate)),
        });
        if (outcome.preserved) {
          lateConflicts += 1;
          elements["import-progress"].value = index + 1;
          continue;
        }
        const result = outcome.result;
        if (!result) throw new Error("Browser returned no cookie after setting it.");
        writeCount += 1;
        const immediate = compareCookieRecords(cookie, result);
        if (immediate.matches) {
          written.push(cookie);
        } else {
          failures.push({ cookie, reason: `Set result: ${immediate.reason}` });
        }
      } catch (error) {
        failures.push({ cookie, reason: sanitizedFailureReason(error, cookie) });
      }
      elements["import-progress"].value = index + 1;
    }

    const verificationSnapshot = await getAllCookiesIncludingPartitions();
    destinationRemovals = countMissingCookieIdentities(
      targetSnapshot.cookies,
      verificationSnapshot.cookies,
    );
    const byKey = new Map();
    for (const cookie of verificationSnapshot.cookies) {
      const key = cookieIdentity(cookie);
      const entries = byKey.get(key) ?? [];
      entries.push(cookie);
      byKey.set(key, entries);
    }

    let verified = 0;
    for (const expected of written) {
      const candidates = byKey.get(cookieIdentity(expected)) ?? [];
      if (candidates.length > 1) {
        failures.push({
          cookie: expected,
          reason: "Multiple origin-bound destination candidates are indistinguishable through the extension API.",
        });
        continue;
      }
      const actual = candidates[0]?.value === expected.value ? candidates[0] : undefined;
      const comparison = compareCookieRecords(expected, actual);
      if (comparison.matches) {
        verified += 1;
        if (comparison.adjustedExpiration) adjustedExpirations += 1;
      } else {
        failures.push({ cookie: expected, reason: comparison.reason });
      }
    }

    const groups = groupFailures(failures);
    const details = groups
      .slice(0, 4)
      .map((group) => `${group.domain}: ${group.count} (${group.reason})`)
      .join("; ");
    const adjusted = adjustedExpirations > 0
      ? ` ${adjustedExpirations.toLocaleString()} persistent expirations were adjusted by Chromium.`
      : "";
    const removals = destinationRemovals > 0
      ? ` ${destinationRemovals.toLocaleString()} pre-existing destination cookie identities disappeared during import; site activity or quota eviction may be responsible.`
      : "";
    const preservedLate = lateConflicts > 0
      ? ` ${lateConflicts.toLocaleString()} destination conflicts were found by the pre-write preserve recheck and skipped.`
      : "";
    if (failures.length === 0 && destinationRemovals === 0) {
      setStatus(
        elements["import-status"],
        lateConflicts > 0 ? "warning" : "success",
        `Imported and verified ${verified.toLocaleString()} cookies.${preservedLate}${adjusted} Reload destination tabs to test sessions.`,
      );
    } else {
      setStatus(
        elements["import-status"],
        "warning",
        `Verified ${verified.toLocaleString()} cookies; ${failures.length.toLocaleString()} failed verification. ${details}${preservedLate}${adjusted}${removals}`,
      );
    }
  } catch (error) {
    setStatus(
      elements["import-status"],
      "error",
      formatImportFailure(writeCount, error.message),
    );
  } finally {
    if (releaseCrossTabLock) await releaseCrossTabLock();
    elements["import-progress"].classList.add("hidden");
    setBusy(elements["import-button"], false, "", "Import inspected cookies");
    elements["import-passphrase"].value = "";
    const completedState = inspectedState;
    inspectedState = null;
    clearCookieValues(completedState?.payload?.cookies);
    endOperation();
  }
}

document.querySelectorAll('input[name="export-scope"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    resetBroadConfirmation();
    if (selectedValue("export-scope") === "all") {
      elements["confirm-all"].checked = false;
    }
    toggleExportScope();
  });
});

elements["export-domains"].addEventListener("input", resetBroadConfirmation);

document.querySelectorAll('input[name="conflict-mode"]').forEach((radio) => {
  radio.addEventListener("change", clearInspection);
});

elements["generate-passphrase"].addEventListener("click", () => {
  const passphrase = generatePassphrase();
  elements["export-passphrase"].value = passphrase;
  elements["export-passphrase-confirm"].value = passphrase;
  elements["show-export-passphrase"].checked = true;
  elements["export-passphrase"].type = "text";
  elements["export-passphrase-confirm"].type = "text";
  elements["export-passphrase"].focus();
  elements["export-passphrase"].select();
});

elements["show-export-passphrase"].addEventListener("change", (event) => {
  const type = event.target.checked ? "text" : "password";
  elements["export-passphrase"].type = type;
  elements["export-passphrase-confirm"].type = type;
});

elements["show-import-passphrase"].addEventListener("change", (event) => {
  elements["import-passphrase"].type = event.target.checked ? "text" : "password";
});

elements["import-file"].addEventListener("change", clearInspection);
elements["import-passphrase"].addEventListener("input", clearInspection);
elements["export-button"].addEventListener("click", handleExport);
elements["inspect-button"].addEventListener("click", handleInspect);
elements["import-button"].addEventListener("click", handleImport);
window.addEventListener("beforeunload", () => {
  clearInspection();
});
toggleExportScope();
initThemeToggle();
