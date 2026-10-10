"use strict";

const state = {
  csrf: "", username: "", config: null, selectedItem: null, items: [], nextCursor: null,
  itemsRequestId: 0, itemsLoading: false, itemsAppending: false,
};
const $ = (selector) => document.querySelector(selector);
const authView = $("#auth-view");
const appView = $("#app-view");

function setMessage(selector, message, error = false) {
  const node = $(selector);
  if (!node) return;
  node.textContent = message || "";
  node.classList.toggle("error", error);
}

class UserFacingError extends Error {
  constructor(message, code = "") {
    super(message);
    this.name = "UserFacingError";
    this.code = code;
  }
}

const KNOWN_API_ERROR_CODES = new Set([
  "invalid_request", "request_too_large", "unauthenticated", "session_check_failed", "permission_denied",
  "forbidden", "not_found", "profile_not_found", "conflict", "registration_conflict", "invalid_credentials",
  "registration_closed", "invalid_invitation", "invalid_filename", "invalid_file", "file_too_large",
  "unsupported_file_type", "mime_mismatch", "image_dimensions_exceeded", "invalid_office_file",
  "archive_limits_exceeded", "active_office_content", "external_relationship", "active_pdf_content",
  "invalid_mp4", "video_limits_exceeded", "video_validation_unavailable", "payload_integrity_mismatch",
  "processing_failed", "native_backend_failed", "retry_limit_exceeded", "benchmark_failed",
  "storage_quota_exceeded", "active_job_exists", "rate_limited", "invalid_state", "service_unavailable",
  "internal_error",
]);

function statusErrorMessage(status) {
  if (status === 401) return "SecureBox couldn't confirm your sign-in. Sign in again, then retry.";
  if (status === 403) return "Your secure session or access level couldn't be confirmed. Refresh the page and try again.";
  if (status === 404) return "This item isn't available. It may have been deleted or belong to another account.";
  if (status === 409) return "This action can't be completed right now. Refresh the page and try again.";
  if (status === 413) return "This request is too large. Choose a smaller file or send less information, then try again.";
  if (status === 415) return "This file type isn't supported. Choose a JPG, JPEG, PNG, PDF, DOCX, XLSX, or MP4 file.";
  if (status === 422) return "Some information is missing or doesn't look right. Review the fields and try again.";
  if (status === 429) return "You've tried this too many times. Wait a little while, then try again.";
  if (status >= 500) return "SecureBox is having trouble completing this request. Try again in a moment.";
  return "SecureBox couldn't complete this request. Check the information and try again.";
}

async function responseError(response) {
  let payload = null;
  try { payload = await response.json(); } catch (_) { /* A proxy or network device may return a non-JSON error page. */ }
  const apiError = payload?.error;
  const code = typeof apiError?.code === "string" && KNOWN_API_ERROR_CODES.has(apiError.code) ? apiError.code : "";
  let message = code && typeof apiError?.message === "string" ? apiError.message : statusErrorMessage(response.status);
  if (code === "rate_limited") {
    const waitSeconds = Number(response.headers.get("Retry-After"));
    if (Number.isFinite(waitSeconds) && waitSeconds > 0) {
      const wait = waitSeconds < 60 ? `${Math.ceil(waitSeconds)} seconds` : `about ${Math.ceil(waitSeconds / 60)} minutes`;
      message += ` The wait is ${wait}.`;
    }
  }
  const requestId = typeof apiError?.request_id === "string" ? apiError.request_id : "";
  if (code === "internal_error" && /^[a-f0-9-]{1,64}$/i.test(requestId)) message += ` Reference: ${requestId}.`;
  return new UserFacingError(message, code);
}

function apiErrorMessage(error) {
  return error instanceof UserFacingError
    ? error.message
    : "Something went wrong. Try again. If the problem continues, contact the project maintainer.";
}

function redirectIfSignedOut(error) {
  if (error?.code !== "unauthenticated" || !state.username) return;
  showAuth();
  setMessage("#auth-message", error.message, true);
}

function setAppMessage(message, error = false) {
  let node = $("#app-message");
  if (!node) {
    const topbar = $(".topbar");
    if (!topbar) return;
    node = document.createElement("p");
    node.id = "app-message";
    node.className = "message";
    node.setAttribute("role", "alert");
    node.setAttribute("aria-live", "polite");
    topbar.insertAdjacentElement("afterend", node);
  }
  node.textContent = message || "";
  node.classList.toggle("error", error);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (state.csrf && options.method && !["GET", "HEAD"].includes(options.method.toUpperCase())) headers.set("X-CSRF-Token", state.csrf);
  let response;
  try {
    response = await fetch(`/api/v1${path}`, { ...options, headers, credentials: "same-origin" });
  } catch (_) {
    throw new UserFacingError("Couldn't connect to SecureBox. Check your internet connection and try again.");
  }
  if (!response.ok) {
    const error = await responseError(response);
    redirectIfSignedOut(error);
    throw error;
  }
  if (response.status === 204) return null;
  try {
    return await response.json();
  } catch (_) {
    throw new UserFacingError("SecureBox sent an unexpected reply. Reload the page and try again.");
  }
}

function showApp(username) {
  state.username = username;
  $("#welcome").textContent = `Signed in as ${username}`;
  setAppMessage("");
  authView.classList.add("hidden");
  appView.classList.remove("hidden");
  loadItems();
}

function showAuth() {
  appView.classList.add("hidden");
  authView.classList.remove("hidden");
  state.csrf = "";
  state.username = "";
  state.itemsRequestId += 1;
  state.itemsLoading = false;
  state.itemsAppending = false;
  state.nextCursor = null;
  state.items = [];
  $("#file-list").replaceChildren();
}

function formatSize(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MiB`;
}

function addCell(row, text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  row.appendChild(cell);
  return cell;
}

function createAction(label, action, danger = false) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `action-btn${danger ? " danger" : ""}`;
  button.textContent = label;
  button.addEventListener("click", action);
  return button;
}

function renderItem(item) {
  const row = document.createElement("tr");
  addCell(row, item.name);
  addCell(row, item.kind === "profile" ? "Profile" : item.name.split(".").pop().toUpperCase());
  addCell(row, formatSize(item.size_bytes));
  const statusCell = addCell(row, "");
  const badge = document.createElement("span");
  badge.className = `status-pill ${item.status}`;
  badge.textContent = ({ queued: "Waiting", processing: "Processing", complete: "Ready", failed: "Needs attention" })[item.status] || "Available";
  statusCell.appendChild(badge);
  if (item.status === "failed") {
    const detail = document.createElement("span");
    detail.className = "helper";
    detail.textContent = item.error_message || "This item could not be processed. Delete it and upload it again.";
    statusCell.appendChild(detail);
  }
  const actions = document.createElement("td");
  actions.className = "item-actions";
  if (item.status === "complete") actions.appendChild(createAction("Compare", () => openComparison(item)));
  actions.appendChild(createAction("Delete", () => deleteItem(item), true));
  row.appendChild(actions);
  return row;
}

function updateLoadMore() {
  const button = $("#load-more");
  button.hidden = !state.nextCursor && !state.itemsAppending;
  button.disabled = state.itemsLoading;
  button.textContent = state.itemsLoading && state.itemsAppending ? "Loading…" : "Load more";
  $("#items-status").textContent = state.itemsLoading
    ? (state.itemsAppending ? "Loading more items…" : "Refreshing items…")
    : "";
}

async function loadItems({ append = false } = {}) {
  if (append && (state.itemsLoading || !state.nextCursor)) return;
  const requestId = ++state.itemsRequestId;
  const cursor = append ? state.nextCursor : null;
  state.itemsLoading = true;
  state.itemsAppending = append;
  if (!append) {
    state.nextCursor = null;
    state.items = [];
    $("#file-list").replaceChildren();
    $("#empty-state").textContent = "Nothing stored yet. Add a synthetic test file or profile above.";
  }
  updateLoadMore();
  try {
    const suffix = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
    const result = await api(`/items?limit=50${suffix}`);
    if (requestId !== state.itemsRequestId) return;
    const incoming = Array.isArray(result.items) ? result.items : [];
    let visibleItems = incoming;
    if (append) {
      const knownIds = new Set(state.items.map((item) => item.id));
      visibleItems = incoming.filter((item) => !knownIds.has(item.id));
      state.items = [...state.items, ...visibleItems];
    } else {
      state.items = incoming;
    }
    state.nextCursor = typeof result.next_cursor === "string" && result.next_cursor ? result.next_cursor : null;
    for (const item of visibleItems) $("#file-list").appendChild(renderItem(item));
    $("#empty-state").classList.toggle("hidden", state.items.length > 0);
    setAppMessage("");
  } catch (error) {
    if (requestId !== state.itemsRequestId) return;
    if (state.items.length === 0) {
      $("#empty-state").textContent = apiErrorMessage(error);
      $("#empty-state").classList.remove("hidden");
    } else {
      setAppMessage(`Could not load more items. ${apiErrorMessage(error)}`, true);
    }
  } finally {
    if (requestId === state.itemsRequestId) {
      state.itemsLoading = false;
      state.itemsAppending = false;
      updateLoadMore();
    }
  }
}

async function pollJob(jobId, itemId) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
    if (job.status === "complete") {
      await loadItems();
      return true;
    }
    if (job.status === "failed") throw new UserFacingError(job.error_message || "The file could not be processed. Check that it is supported, then upload it again.");
    if (itemId && attempt % 3 === 0) await loadItems();
    await new Promise((resolve) => window.setTimeout(resolve, 1500));
  }
  throw new UserFacingError("This is taking longer than expected. Refresh the item list in a moment before uploading the file again.");
}

function uploadWithProgress(file) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", file, file.name);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/files");
    xhr.withCredentials = true;
    xhr.setRequestHeader("Accept", "application/json");
    if (state.csrf) xhr.setRequestHeader("X-CSRF-Token", state.csrf);
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100);
        const step = percent >= 100 ? "p100" : percent >= 75 ? "p75" : percent >= 50 ? "p50" : "p25";
        $("#progress-bar").className = `progress-bar ${step}`;
      }
    });
    xhr.addEventListener("load", async () => {
      let payload = {};
      try { payload = JSON.parse(xhr.responseText); } catch (_) { /* handled below */ }
      if (xhr.status >= 200 && xhr.status < 300) {
        if (typeof payload?.job_id !== "string" || typeof payload?.item_id !== "string") {
          reject(new UserFacingError("SecureBox received the upload but couldn't confirm that processing started. Refresh the item list before uploading again."));
        } else resolve(payload);
      } else {
        const error = await responseError({
          status: xhr.status,
          headers: { get: (name) => xhr.getResponseHeader(name) },
          json: async () => payload,
        });
        redirectIfSignedOut(error);
        reject(error);
      }
    });
    xhr.addEventListener("error", () => reject(new UserFacingError("The upload couldn't reach SecureBox. Check your internet connection and try again.")));
    xhr.addEventListener("abort", () => reject(new UserFacingError("The upload was cancelled before it finished.")));
    xhr.send(form);
  });
}

async function handleFile(file) {
  const ext = file.name.split(".").pop().toLowerCase();
  const limit = state.config?.max_file_bytes?.[ext];
  if (!limit) {
    setMessage("#upload-message", "Choose a JPG, JPEG, PNG, PDF, DOCX, XLSX, or MP4 file.", true);
    return;
  }
  if (file.size > limit) {
    setMessage("#upload-message", `This file is larger than the ${formatSize(limit)} limit. Choose a smaller file and try again.`, true);
    return;
  }
  $("#upload-progress").classList.remove("hidden");
  $("#progress-bar").className = "progress-bar";
  setMessage("#upload-message", "");
  $("#upload-status").textContent = "Uploading and validating…";
  try {
    const queued = await uploadWithProgress(file);
    $("#upload-status").textContent = "Encrypting three variants…";
    await pollJob(queued.job_id, queued.item_id);
    $("#progress-bar").className = "progress-bar p100";
    $("#upload-status").textContent = "Saved and encrypted.";
  } catch (error) {
    setMessage("#upload-message", apiErrorMessage(error), true);
    $("#upload-status").textContent = "Upload not completed.";
  }
}

async function saveProfile(event) {
  event.preventDefault();
  const fields = new FormData(event.currentTarget);
  const profile = {};
  for (const [name, value] of fields.entries()) if (String(value).trim()) profile[name] = String(value).trim();
  setMessage("#profile-message", "Encrypting profile…");
  try {
    const queued = await api("/me/profile", { method: "PUT", body: JSON.stringify(profile) });
    await pollJob(queued.job_id, queued.item_id);
    setMessage("#profile-message", "Profile snapshot saved.");
  } catch (error) {
    setMessage("#profile-message", apiErrorMessage(error), true);
  }
}

async function loadProfile() {
  try {
    const result = await api("/me/profile?algorithm=aes");
    const profile = result.profile;
    for (const name of ["display_name", "contact_email", "phone", "address", "date_of_birth", "national_id"]) {
      const input = $(`#profile-form [name="${name}"]`);
      input.value = profile[name] || "";
    }
    setMessage("#profile-message", "Decrypted profile loaded for this session.");
  } catch (error) {
    setMessage("#profile-message", apiErrorMessage(error), true);
  }
}

async function openComparison(item) {
  state.selectedItem = item;
  $("#compare-title").textContent = item.name;
  $("#compare-grid").replaceChildren();
  $("#benchmark-output").classList.add("hidden");
  $("#benchmark-message").textContent = "Loading comparison…";
  $("#compare-panel").classList.remove("hidden");
  $("#load-profile-compare").classList.toggle("hidden", item.kind !== "profile");
  try {
    const result = await api(`/items/${encodeURIComponent(item.id)}/variants`);
    for (const variant of result.variants) {
      const card = document.createElement("article");
      card.className = "variant-card";
      const title = document.createElement("h4");
      title.textContent = variant.algorithm.toUpperCase();
      const mode = document.createElement("p");
      mode.className = "variant-mode";
      mode.textContent = variant.mode;
      card.append(title, mode);
      card.appendChild(stat("Backend", variant.backend));
      card.appendChild(stat("Ciphertext", formatSize(variant.ciphertext_bytes)));
      card.appendChild(stat("Encrypt time", `${variant.encryption_ms.toFixed(4)} ms`));
      const preview = document.createElement("code");
      preview.className = "variant-preview";
      const previewData = await api(`/items/${encodeURIComponent(item.id)}/variants/${variant.algorithm}/ciphertext`);
      preview.textContent = previewData.preview_base64;
      const download = createAction(`Download via ${variant.algorithm.toUpperCase()}`, () => downloadVariant(item, variant.algorithm));
      card.append(preview, download);
      $("#compare-grid").appendChild(card);
    }
    $("#benchmark-message").textContent = "";
  } catch (error) {
    setMessage("#benchmark-message", apiErrorMessage(error), true);
  }
}

async function downloadVariant(item, algorithm) {
  try {
    let response;
    try {
      response = await fetch(`/api/v1/items/${encodeURIComponent(item.id)}/variants/${algorithm}/download`, {
        headers: { Accept: "application/octet-stream, application/json" },
        credentials: "same-origin",
      });
    } catch (_) {
      throw new UserFacingError("Couldn't connect to SecureBox. Check your internet connection and try the download again.");
    }
    if (!response.ok) {
      const error = await responseError(response);
      redirectIfSignedOut(error);
      throw error;
    }
    const file = await response.blob();
    const link = document.createElement("a");
    const objectUrl = URL.createObjectURL(file);
    link.href = objectUrl;
    link.rel = "noopener";
    const disposition = response.headers.get("Content-Disposition") || "";
    const encodedName = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
    const plainName = disposition.match(/filename="?([^";]+)"?/i)?.[1];
    try { link.download = encodedName ? decodeURIComponent(encodedName) : plainName || item.name || "download"; }
    catch (_) { link.download = item.name || "download"; }
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    setAppMessage("");
  } catch (error) {
    setAppMessage(apiErrorMessage(error), true);
  }
}

function stat(label, value) {
  const p = document.createElement("p");
  p.className = "variant-stat";
  const strong = document.createElement("strong");
  strong.textContent = `${label}: `;
  p.append(strong, document.createTextNode(value));
  return p;
}

async function runBenchmark() {
  if (!state.selectedItem) return;
  setMessage("#benchmark-message", "Queueing benchmark…");
  $("#benchmark-output").classList.add("hidden");
  try {
    const queued = await api(`/items/${encodeURIComponent(state.selectedItem.id)}/benchmarks`, { method: "POST" });
    for (let attempt = 0; attempt < 240; attempt += 1) {
      const run = await api(`/benchmark-runs/${encodeURIComponent(queued.run_id)}`);
      if (run.status === "complete") {
        $("#benchmark-output").textContent = JSON.stringify(run.results, null, 2);
        $("#benchmark-output").classList.remove("hidden");
        setMessage("#benchmark-message", "Five samples completed for each algorithm.");
        return;
      }
      if (run.status === "failed") throw new UserFacingError(run.error_message || "The comparison couldn't finish. Try again later.");
      setMessage("#benchmark-message", "Running bounded comparison…");
      await new Promise((resolve) => window.setTimeout(resolve, 1500));
    }
    throw new UserFacingError("The comparison is taking longer than expected. Check again shortly before starting another one.");
  } catch (error) {
    setMessage("#benchmark-message", apiErrorMessage(error), true);
  }
}

async function deleteItem(item) {
  if (!window.confirm(`Delete “${item.name}”?`)) return;
  try {
    await api(`/items/${encodeURIComponent(item.id)}`, { method: "DELETE" });
    $("#compare-panel").classList.add("hidden");
    await loadItems();
  } catch (error) {
    setAppMessage(apiErrorMessage(error), true);
  }
}

function switchAuth(register) {
  $("#login-form").classList.toggle("hidden", register);
  $("#register-form").classList.toggle("hidden", !register);
  $("#show-login").classList.toggle("active", !register);
  $("#show-register").classList.toggle("active", register);
  $("#show-login").setAttribute("aria-selected", String(!register));
  $("#show-register").setAttribute("aria-selected", String(register));
  setMessage("#auth-message", "");
}

async function bootstrap() {
  try {
    state.config = await api("/config");
    const mode = state.config.registration_mode;
    $("#registration-note").textContent = mode === "closed" ? "Account registration is closed." : mode === "invite" ? "Account creation requires an invitation code." : "Use synthetic data. Registration is open for local development.";
    $("#show-register").classList.toggle("hidden", mode === "closed");
    $("#invitation-field").classList.toggle("hidden", mode !== "invite");
    const session = await api("/auth/session");
    if (session.authenticated) {
      state.csrf = session.csrf_token;
      showApp(session.username);
    }
  } catch (error) {
    setMessage("#auth-message", apiErrorMessage(error), true);
  }
}

$("#show-login").addEventListener("click", () => switchAuth(false));
$("#show-register").addEventListener("click", () => switchAuth(true));
$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  try {
    const result = await api("/auth/login", { method: "POST", body: JSON.stringify({ username: form.get("username"), password: form.get("password") }) });
    state.csrf = result.csrf_token;
    formElement.reset();
    showApp(result.username);
  } catch (error) {
    setMessage("#auth-message", apiErrorMessage(error), true);
  }
});
$("#register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const payload = { username: form.get("username"), password: form.get("password") };
  if (form.get("invitation_code")) payload.invitation_code = form.get("invitation_code");
  try {
    await api("/auth/register", { method: "POST", body: JSON.stringify(payload) });
    formElement.reset();
    switchAuth(false);
    setMessage("#auth-message", "Account created. Sign in to continue.");
  } catch (error) {
    setMessage("#auth-message", apiErrorMessage(error), true);
  }
});
$("#logout").addEventListener("click", async () => {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch (error) {
    setAppMessage(`Secure sign-out couldn't be confirmed. ${apiErrorMessage(error)}`, true);
    return;
  }
  showAuth();
  setMessage("#auth-message", "You are signed out.");
});
$("#file-upload").addEventListener("change", (event) => {
  const file = event.currentTarget.files?.[0];
  if (file) handleFile(file);
  event.currentTarget.value = "";
});
$("#profile-form").addEventListener("submit", saveProfile);
$("#load-profile").addEventListener("click", loadProfile);
$("#refresh-items").addEventListener("click", loadItems);
$("#load-more").addEventListener("click", () => loadItems({ append: true }));
$("#close-compare").addEventListener("click", () => $("#compare-panel").classList.add("hidden"));
$("#run-benchmark").addEventListener("click", runBenchmark);
$("#load-profile-compare").addEventListener("click", loadProfile);
$("#delete-account").addEventListener("click", async () => {
  const approved = window.confirm("Permanently delete your account and all SecureBox items? Provider backups may remain until their stated expiry.");
  if (!approved) return;
  const button = $("#delete-account");
  button.disabled = true;
  try {
    await api("/me", { method: "DELETE" });
    showAuth();
    setMessage("#auth-message", "Your account is closed. Encrypted objects are being removed, with retries if storage is temporarily unavailable.");
  } catch (error) {
    setAppMessage(apiErrorMessage(error), true);
  } finally {
    button.disabled = false;
  }
});

bootstrap();
