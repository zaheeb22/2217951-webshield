// Shared API helper used by every frontend page.
// It handles the base URL, cookies, CSRF tokens, and download responses.

const apiHost =
  ["0.0.0.0", "localhost", "::1"].includes(window.location.hostname)
    ? "127.0.0.1"
    : window.location.hostname || "127.0.0.1";
const externalStaticPorts = new Set(["5500"]);
const defaultApiRoot =
  window.location.protocol.startsWith("http") &&
  !externalStaticPorts.has(window.location.port)
    ? `${window.location.origin}/api`
    : `http://${apiHost}:5000/api`;
const API_ROOT = window.WEBSHIELD_API_ROOT || defaultApiRoot;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
let csrfToken = null;

function setCsrfToken(nextToken) {
  // Keep the newest token in memory so later POST/PATCH requests can reuse it.
  if (typeof nextToken === "string" && nextToken.length) {
    csrfToken = nextToken;
  }
}

async function fetchCsrfToken() {
  // Ask the backend for a token only when the page does not already have one.
  if (csrfToken) {
    return csrfToken;
  }

  let response;

  try {
    response = await fetch(`${API_ROOT}/auth/csrf-token`, {
      credentials: "include",
    });
  } catch {
    throw new Error(`Cannot reach backend API at ${API_ROOT}.`);
  }

  const data = await response.json();
  setCsrfToken(data.csrfToken);
  return csrfToken;
}

async function request(path, options = {}, retried = false) {
  // This is the main wrapper every page uses instead of calling fetch directly.
  const method = (options.method || "GET").toUpperCase();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (!SAFE_METHODS.has(method)) {
    headers["X-CSRF-Token"] = await fetchCsrfToken();
  }

  let response;

  try {
    response = await fetch(`${API_ROOT}${path}`, {
      method,
      headers,
      credentials: "include",
      body: options.body,
    });
  } catch {
    throw new Error(`Cannot reach backend API at ${API_ROOT}.`);
  }

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (data && typeof data === "object" && data.csrfToken) {
    setCsrfToken(data.csrfToken);
  }

  if (!response.ok) {
    if (
      !retried &&
      !SAFE_METHODS.has(method) &&
      typeof data === "object" &&
      data.code === "csrf_failed"
    ) {
      csrfToken = null;
      return request(path, options, true);
    }

    const message =
      typeof data === "string" ? data : data.error || "Request failed.";
    const error = new Error(message);
    error.status = response.status;
    error.code = typeof data === "object" ? data.code : undefined;
    error.details = typeof data === "object" ? data.details : undefined;
    throw error;
  }

  return data;
}

async function download(path, filename) {
  // Download CSV or JSON files produced by the admin and audit endpoints.
  let response;

  try {
    response = await fetch(`${API_ROOT}${path}`, {
      credentials: "include",
    });
  } catch {
    throw new Error(`Cannot reach backend API at ${API_ROOT}.`);
  }

  if (!response.ok) {
    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : await response.text();
    const message =
      typeof data === "string" ? data : data.error || "Download failed.";
    throw new Error(message);
  }

  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

export { API_ROOT, download, fetchCsrfToken, request, setCsrfToken };
