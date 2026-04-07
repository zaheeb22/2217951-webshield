// Script for the dedicated audit page.
// It is an admin-only view focused on filtering and exporting audit events.

import { download, request } from "./api.js?v=20260404d";
import {
  createStatusChip,
  formatDateTime,
  getAuditThreatMeta,
  renderEmptyState,
  renderInfoRows,
  setMessage,
} from "./ui.js?v=20260404g";

const auditAdminInfo = document.querySelector("#auditAdminInfo");
const auditPageMessage = document.querySelector("#auditPageMessage");
const auditSummary = document.querySelector("#auditSummary");
const auditFilterForm = document.querySelector("#auditFilterForm");
const auditLogList = document.querySelector("#auditLogList");
const auditMessage = document.querySelector("#auditMessage");
const auditCsvButton = document.querySelector("#auditCsvButton");
const auditJsonButton = document.querySelector("#auditJsonButton");
const logoutButton = document.querySelector("#logoutButton");

function formToParams(form) {
  // Convert the filter form into URL query parameters for the audit API.
  const params = new URLSearchParams();
  const formData = new FormData(form);
  for (const [key, value] of formData.entries()) {
    const trimmed = String(value).trim();
    if (trimmed) {
      params.set(key, trimmed);
    }
  }
  return params;
}

async function ensureAdminSession() {
  // This page is for admins only, so it checks auth and role up front.
  const sessionData = await request("/auth/session");

  if (!sessionData.authenticated) {
    window.location.href = "login.html";
    throw new Error("Authentication required.");
  }

  renderInfoRows(auditAdminInfo, [
    ["Username", sessionData.user.username],
    ["Email", sessionData.user.email],
    ["Role", sessionData.user.role],
    ["Last login", formatDateTime(sessionData.user.lastLoginAt)],
  ]);

  if (sessionData.user.role !== "admin") {
    throw new Error("This page is restricted to admin users.");
  }

  return sessionData.user;
}

function buildAuditCard(item) {
  // Turn one audit event into a readable card with a severity label.
  const article = document.createElement("article");
  const threat = getAuditThreatMeta(item.action, item.targetType);
  article.className = `entry-card audit-card audit-level-${threat.level}`;

  const header = document.createElement("div");
  header.className = "audit-card-header";

  const title = document.createElement("h3");
  title.textContent = item.action.replaceAll("_", " ");

  const meta = document.createElement("p");
  meta.className = "entry-meta";
  meta.textContent =
    `Actor: ${item.actor?.username || "system"} | ` +
    `Target: ${item.targetType}${item.targetId ? ` #${item.targetId}` : ""} | ` +
    `Created: ${formatDateTime(item.createdAt)}`;

  const detail = document.createElement("p");
  detail.textContent = item.detail || "No detail recorded for this event.";

  header.append(title, createStatusChip(threat.level));

  const threatDetail = document.createElement("p");
  threatDetail.className = "section-label";
  threatDetail.textContent = threat.description;

  article.append(header, meta, threatDetail, detail);
  return article;
}

async function loadSummary() {
  // The audit page reuses the admin overview endpoint for top-level counts.
  const data = await request("/admin/overview");

  renderInfoRows(auditSummary, [
    ["Audit events", String(data.summary.auditEvents)],
    ["Failed logins (24h)", String(data.summary.failedLoginsLast24h)],
    ["Locked attempts", String(data.summary.lockedLoginAttempts)],
    ["Lab mode", data.summary.labMode],
    ["Pending feedback", String(data.summary.pendingFeedback)],
    ["Resolved feedback", String(data.summary.resolvedFeedback)],
  ]);
}

async function loadAuditLogs() {
  // Load audit rows using the current filter form values.
  const params = formToParams(auditFilterForm);
  const query = params.toString();
  const data = await request(`/admin/audit-logs${query ? `?${query}` : ""}`);

  if (!data.items.length) {
    renderEmptyState(auditLogList, "No audit events match the current filters.");
    return;
  }

  auditLogList.innerHTML = "";
  data.items.forEach((item) => {
    auditLogList.append(buildAuditCard(item));
  });
}

auditFilterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAuditLogs();
});

auditCsvButton.addEventListener("click", async () => {
  // Export the same filtered results the page is currently showing.
  try {
    const query = formToParams(auditFilterForm).toString();
    await download(
      `/admin/audit-logs/export?${query ? `${query}&` : ""}format=csv`,
      "webshield-audit-log-export.csv"
    );
    setMessage(auditMessage, "Audit log CSV export downloaded.", "success");
  } catch (error) {
    setMessage(auditMessage, error.message, "error");
  }
});

auditJsonButton.addEventListener("click", async () => {
  // JSON export is useful when the audit data will be reused elsewhere.
  try {
    const query = formToParams(auditFilterForm).toString();
    await download(
      `/admin/audit-logs/export?${query ? `${query}&` : ""}format=json`,
      "webshield-audit-log-export.json"
    );
    setMessage(auditMessage, "Audit log JSON export downloaded.", "success");
  } catch (error) {
    setMessage(auditMessage, error.message, "error");
  }
});

logoutButton.addEventListener("click", async () => {
  await request("/auth/logout", { method: "POST" });
  window.location.href = "login.html";
});

async function initialiseAuditPage() {
  // Start the audit page by verifying admin access and loading initial data.
  try {
    await ensureAdminSession();
    setMessage(
      auditPageMessage,
      "Administrator session verified. Audit trail controls are available.",
      "success"
    );
    await Promise.all([loadSummary(), loadAuditLogs()]);
  } catch (error) {
    setMessage(auditPageMessage, error.message, "error");
    if (error.message === "This page is restricted to admin users.") {
      window.setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 1200);
    }
  }
}

initialiseAuditPage();
