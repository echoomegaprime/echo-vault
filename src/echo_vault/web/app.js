"use strict";

const encoder = new TextEncoder();
const state = {
  clientId: "",
  key: null,
  namespace: "demo",
  secrets: [],
  lockTimer: null,
};

const byId = (id) => document.getElementById(id);

function toBase64Url(bytes) {
  let binary = "";
  for (const value of new Uint8Array(bytes)) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function importSigningKey(encoded) {
  const material = fromBase64Url(encoded.trim());
  if (material.byteLength < 32) throw new Error("Client signing secret is too short.");
  return crypto.subtle.importKey(
    "raw",
    material,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signedHeaders(method, path, query, body) {
  if (!state.clientId || !state.key) throw new Error("Unlock the console first.");
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(24)));
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(body));
  const canonical = [
    "echo-vault-hmac-v1",
    method.toUpperCase(),
    path,
    query,
    Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join(""),
    timestamp,
    nonce,
  ].join("\n");
  const signature = await crypto.subtle.sign("HMAC", state.key, encoder.encode(canonical));
  return {
    "X-Vault-Client": state.clientId,
    "X-Vault-Timestamp": timestamp,
    "X-Vault-Nonce": nonce,
    "X-Vault-Signature": toBase64Url(signature),
  };
}

async function vaultRequest(method, path, options = {}) {
  const query = options.query ? new URLSearchParams(options.query).toString() : "";
  const body = options.payload === undefined ? "" : JSON.stringify(options.payload);
  const headers = await signedHeaders(method, path, query, body);
  if (body) headers["Content-Type"] = "application/json";
  const response = await fetch(path + (query ? `?${query}` : ""), {
    method,
    headers,
    body: body || undefined,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  let result = null;
  try {
    result = await response.json();
  } catch {
    result = { detail: "The server returned an unreadable response." };
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${result.detail || "Request failed"}`);
  touchSession();
  return result;
}

function showToast(message, kind = "success") {
  const toast = byId("toast");
  toast.textContent = message;
  toast.dataset.kind = kind;
  toast.classList.add("is-visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("is-visible"), 4200);
}

function requireSession() {
  if (!state.key) {
    showToast("Unlock the operator session first.", "error");
    byId("client-id").focus();
    return false;
  }
  return true;
}

function touchSession() {
  if (!state.key) return;
  window.clearTimeout(state.lockTimer);
  state.lockTimer = window.setTimeout(() => lockSession("Session locked after 15 minutes."), 900000);
}

function lockSession(message = "Signing material cleared from this tab.") {
  state.clientId = "";
  state.key = null;
  state.secrets = [];
  window.clearTimeout(state.lockTimer);
  byId("client-id").value = "";
  byId("client-secret").value = "";
  byId("create-secret").value = "";
  byId("update-secret").value = "";
  byId("revealed-secret").value = "";
  byId("session-indicator").dataset.state = "locked";
  byId("session-label").textContent = "Session locked";
  byId("lock-button").disabled = true;
  byId("unlock-card").classList.remove("is-hidden");
  byId("secret-rows").innerHTML = '<tr><td colspan="5" class="empty-state">Unlock, then load a namespace.</td></tr>';
  byId("audit-status").textContent = "Locked";
  byId("secret-count").textContent = "No metadata loaded";
  showToast(message);
}

function shortHash(value) {
  if (!value) return "Unavailable";
  return value.length > 20 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function actionButton(label, action, name, version, style = "button-secondary") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `button button-small ${style}`;
  button.textContent = label;
  button.dataset.action = action;
  button.dataset.name = name;
  button.dataset.version = String(version);
  return button;
}

function renderSecrets() {
  const rows = byId("secret-rows");
  rows.replaceChildren();
  if (!state.secrets.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="5" class="empty-state">No active secrets in this namespace.</td>';
    rows.append(row);
    return;
  }
  for (const item of state.secrets) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = item.name;
    const version = document.createElement("td");
    version.textContent = `v${item.current_version}`;
    const key = document.createElement("td");
    key.textContent = item.key_id;
    const updated = document.createElement("td");
    updated.textContent = formatDate(item.updated_at);
    const actions = document.createElement("td");
    actions.className = "table-actions";
    actions.append(
      actionButton("Reveal", "reveal", item.name, item.current_version),
      actionButton("Rotate", "rotate", item.name, item.current_version),
      actionButton("Delete", "delete", item.name, item.current_version, "button-danger"),
    );
    row.append(name, version, key, updated, actions);
    rows.append(row);
  }
}

async function loadNamespace() {
  if (!requireSession()) return;
  const namespace = byId("namespace").value.trim();
  if (!namespace) return;
  try {
    const result = await vaultRequest("GET", "/v1/secrets", { query: { namespace } });
    state.namespace = namespace;
    state.secrets = result;
    byId("namespace-status").textContent = namespace;
    byId("secret-count").textContent = `${result.length} active secret${result.length === 1 ? "" : "s"}`;
    renderSecrets();
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function revealSecret(name) {
  try {
    const result = await vaultRequest("GET", `/v1/secrets/${state.namespace}/${name}`);
    byId("secret-dialog-title").textContent = name;
    byId("revealed-secret").value = result.secret;
    byId("secret-dialog").showModal();
    window.setTimeout(() => {
      if (byId("secret-dialog").open) {
        byId("revealed-secret").value = "";
        byId("secret-dialog").close();
        showToast("Revealed value cleared after 30 seconds.");
      }
    }, 30000);
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function verifyAudit() {
  if (!requireSession()) return;
  try {
    const result = await vaultRequest("GET", "/v1/audit/verify");
    const seal = document.querySelector(".audit-seal");
    seal.classList.toggle("is-valid", result.valid);
    seal.classList.toggle("is-invalid", !result.valid);
    byId("audit-result-title").textContent = result.valid ? "Audit chain verified" : "Audit integrity failed";
    byId("audit-result-copy").textContent = result.valid
      ? "Every retained event links correctly to the independent signed terminal anchor."
      : `Verification stopped at event ${result.first_bad_event_id || "checkpoint"}. Protected operations remain fail-closed.`;
    byId("audit-events").textContent = String(result.events);
    byId("audit-database").textContent = shortHash(result.database_id);
    byId("audit-root").textContent = shortHash(result.terminal_hash);
    byId("audit-status").textContent = result.valid ? "Verified" : "Failed";
    byId("audit-detail").textContent = `${result.events} anchored events`;
    showToast(result.valid ? "Audit verification passed." : "Audit verification failed.", result.valid ? "success" : "error");
  } catch (error) {
    byId("audit-status").textContent = "Unavailable";
    showToast(error.message, "error");
  }
}

function activatePanel(panelId) {
  document.querySelectorAll(".panel").forEach((panel) => {
    const active = panel.id === panelId;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
  document.querySelectorAll(".rail-link").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.panel === panelId);
  });
}

byId("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!crypto?.subtle) {
    showToast("Web Crypto is unavailable. Use HTTPS or a loopback URL.", "error");
    return;
  }
  try {
    state.clientId = byId("client-id").value.trim();
    state.key = await importSigningKey(byId("client-secret").value);
    byId("client-secret").value = "";
    byId("session-indicator").dataset.state = "ready";
    byId("session-label").textContent = `Unlocked as ${state.clientId}`;
    byId("lock-button").disabled = false;
    byId("unlock-card").classList.add("is-hidden");
    touchSession();
    showToast("Session unlocked. Signing material is memory-only.");
    await loadNamespace();
  } catch (error) {
    state.clientId = "";
    state.key = null;
    showToast(error.message, "error");
  }
});

byId("namespace-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadNamespace();
});
byId("refresh-button").addEventListener("click", loadNamespace);
byId("lock-button").addEventListener("click", () => lockSession());
byId("verify-audit-button").addEventListener("click", verifyAudit);

byId("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!requireSession()) return;
  const secretField = byId("create-secret");
  try {
    await vaultRequest("POST", `/v1/secrets/${state.namespace}/${byId("create-name").value.trim()}`, {
      payload: {
        secret: secretField.value,
        username: byId("create-username").value.trim() || null,
        metadata: {},
        tags: byId("create-tags").value.split(",").map((item) => item.trim()).filter(Boolean),
      },
    });
    event.target.reset();
    secretField.value = "";
    showToast("Secret encrypted and stored.");
    await loadNamespace();
  } catch (error) {
    secretField.value = "";
    showToast(error.message, "error");
  }
});

byId("update-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!requireSession()) return;
  const secretField = byId("update-secret");
  try {
    await vaultRequest("PATCH", `/v1/secrets/${state.namespace}/${byId("update-name").value}`, {
      payload: {
        secret: secretField.value,
        username: null,
        metadata: {},
        tags: [],
        expected_version: Number(byId("update-version").value),
      },
    });
    event.target.reset();
    secretField.value = "";
    showToast("New secret version stored.");
    await loadNamespace();
  } catch (error) {
    secretField.value = "";
    showToast(error.message, "error");
  }
});

byId("secret-rows").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  if (button.dataset.action === "reveal") revealSecret(button.dataset.name);
  if (button.dataset.action === "rotate") {
    byId("update-name").value = button.dataset.name;
    byId("update-version").value = button.dataset.version;
    byId("update-secret").focus();
  }
  if (button.dataset.action === "delete") {
    byId("delete-name").value = button.dataset.name;
    byId("delete-version").value = button.dataset.version;
    byId("delete-confirmation").value = "";
    byId("delete-dialog").showModal();
  }
});

byId("delete-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = byId("delete-name").value;
  if (byId("delete-confirmation").value !== name) {
    showToast("The confirmation does not match the secret name.", "error");
    return;
  }
  try {
    await vaultRequest("DELETE", `/v1/secrets/${state.namespace}/${name}`, {
      payload: { expected_version: Number(byId("delete-version").value) },
    });
    byId("delete-dialog").close();
    showToast("Secret soft-deleted.");
    await loadNamespace();
  } catch (error) {
    showToast(error.message, "error");
  }
});

document.querySelectorAll("[data-close-delete]").forEach((button) => {
  button.addEventListener("click", () => byId("delete-dialog").close());
});

byId("copy-secret").addEventListener("click", async () => {
  const value = byId("revealed-secret").value;
  if (!value) return;
  await navigator.clipboard.writeText(value);
  showToast("Secret copied. Clear your clipboard after use.");
});

byId("secret-dialog").addEventListener("close", () => {
  byId("revealed-secret").value = "";
});

byId("rekey-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!requireSession()) return;
  const keyId = byId("rekey-id").value.trim();
  try {
    const result = await vaultRequest("POST", `/v1/admin/rekey/${keyId}`);
    event.target.reset();
    showToast(`${result.versions_rekeyed} historical versions rekeyed.`);
  } catch (error) {
    showToast(error.message, "error");
  }
});

document.querySelectorAll(".rail-link").forEach((button) => {
  button.addEventListener("click", () => activatePanel(button.dataset.panel));
});

for (const eventName of ["pointerdown", "keydown"]) {
  window.addEventListener(eventName, touchSession, { passive: true });
}
window.addEventListener("pagehide", () => lockSession("Session closed."));

async function checkRuntime() {
  try {
    const [health, ready] = await Promise.all([
      fetch("/healthz", { cache: "no-store", credentials: "omit" }),
      fetch("/readyz", { cache: "no-store", credentials: "omit" }),
    ]);
    byId("runtime-status").textContent = ready.ok ? "Ready" : health.ok ? "Degraded" : "Offline";
    byId("runtime-detail").textContent = ready.ok ? "Integrity checkpoint verified" : "Readiness gate is closed";
  } catch {
    byId("runtime-status").textContent = "Offline";
    byId("runtime-detail").textContent = "Service is unreachable";
  }
}

checkRuntime();
