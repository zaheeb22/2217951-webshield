// Script for the main admin dashboard.
// This page now acts as the admin home and keeps only shared overview controls.

import { download, request } from "./api.js?v=20260408a";
import {
  createStatusChip,
  formatDateTime,
  renderEmptyState,
  renderInfoRows,
  setMessage,
} from "./ui.js?v=20260408a";

const adminInfo = document.querySelector("#adminInfo");
const adminMessage = document.querySelector("#adminMessage");
const adminOverview = document.querySelector("#adminOverview");
const loginAttemptList = document.querySelector("#loginAttemptList");
const loginAttemptMessage = document.querySelector("#loginAttemptMessage");
const refreshAttemptsButton = document.querySelector("#refreshAttemptsButton");
const resetAllAttemptsButton = document.querySelector("#resetAllAttemptsButton");
const securitySummary = document.querySelector("#securitySummary");
const securityTableBody = document.querySelector("#securityTableBody");
const securityMessage = document.querySelector("#securityMessage");
const securityCsvButton = document.querySelector("#securityCsvButton");
const securityJsonButton = document.querySelector("#securityJsonButton");
const logoutButton = document.querySelector("#logoutButton");

async function ensureAdminSession() {
  // Confirm the viewer is signed in and has the admin role before loading data.
  const sessionData = await request("/auth/session");

  if (!sessionData.authenticated) {
    window.location.href = "login.html";
    throw new Error("Authentication required.");
  }

  renderInfoRows(adminInfo, [
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

function buildLoginAttemptCard(item) {
  // Show one tracked failed-login entry from the in-memory rate-limit store.
  const article = document.createElement("article");
  article.className = "entry-card";

  const title = document.createElement("h3");
  title.textContent = item.email || "unknown";

  const meta = document.createElement("p");
  meta.className = "entry-meta";
  meta.textContent =
    `IP: ${item.ipAddress || "local"} | Failed attempts: ${item.count} | ` +
    `First failure: ${formatDateTime(item.firstFailedAt)}`;

  const state = document.createElement("p");
  state.textContent = item.isLocked
    ? `Locked for ${item.remainingLockSeconds} more seconds.`
    : "Tracked but not currently locked.";

  const controls = document.createElement("div");
  controls.className = "admin-controls";

  const resetButton = document.createElement("button");
  resetButton.type = "button";
  resetButton.textContent = "Reset Attempt";
  resetButton.addEventListener("click", async () => {
    try {
      await request("/admin/login-attempts/reset", {
        method: "POST",
        body: JSON.stringify({ identifier: item.identifier }),
      });
      setMessage(loginAttemptMessage, "Login attempt entry cleared.", "success");
      await Promise.all([loadOverview(), loadLoginAttempts(), loadAuditLogs()]);
    } catch (error) {
      setMessage(loginAttemptMessage, error.message, "error");
    }
  });

  controls.append(resetButton);
  article.append(
    title,
    createStatusChip(item.isLocked ? "locked" : "tracked"),
    meta,
    state,
    controls
  );
  return article;
}

function renderSecurityTable(items) {
  // Show the backend's secure-vs-demo scenario summary as a comparison table.
  securityTableBody.innerHTML = "";
  const labels = [
    "Vulnerability",
    "Review Method",
    "Demo Route",
    "Before Mitigation",
    "After Mitigation",
    "Mitigation",
    "Demo Mode",
  ];

  items.forEach((item) => {
    const row = document.createElement("tr");
    const cells = [
      item.vulnerability,
      item.reviewMethod,
      item.demoRoute,
      item.beforeState,
      item.afterState,
      item.mitigation,
      item.demoEnabled ? "enabled" : "disabled",
    ];

    cells.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.dataset.label = labels[index];
      cell.textContent = value;
      row.append(cell);
    });

    securityTableBody.append(row);
  });
}

async function loadOverview() {
  // Load the headline numbers used across the admin dashboard.
  const data = await request("/admin/overview");

  renderInfoRows(adminOverview, [
    ["Registered users", String(data.summary.totalUsers)],
    ["Active users", String(data.summary.activeUsers)],
    ["Disabled users", String(data.summary.disabledUsers)],
    ["Administrators", String(data.summary.adminUsers)],
    ["Support tickets", String(data.summary.totalTickets)],
    ["Pending tickets", String(data.summary.pendingTickets)],
    ["Reviewed tickets", String(data.summary.reviewedTickets)],
    ["Resolved tickets", String(data.summary.resolvedTickets)],
    ["Audit events", String(data.summary.auditEvents)],
    ["Failed logins (24h)", String(data.summary.failedLoginsLast24h)],
    ["Locked attempts", String(data.summary.lockedLoginAttempts)],
    ["Lab mode", data.summary.labMode],
  ]);
}

async function loadLoginAttempts() {
  // Load the current rate-limit tracker entries for review or reset.
  const data = await request("/admin/login-attempts");

  if (!data.items.length) {
    renderEmptyState(
      loginAttemptList,
      "No tracked failed login attempts are currently stored."
    );
    return;
  }

  loginAttemptList.innerHTML = "";
  data.items.forEach((item) => {
    loginAttemptList.append(buildLoginAttemptCard(item));
  });
}

async function loadSecurityReport() {
  // Load the backend's built-in security comparison summary.
  const data = await request("/admin/security-report");

  renderInfoRows(securitySummary, [
    ["Secure mode", data.summary.demoEnabled ? "No" : "Yes"],
    ["Demo mode", data.summary.demoEnabled ? "Enabled" : "Disabled"],
    ["Lab mode value", data.summary.labMode],
    ["Tracked vulnerabilities", String(data.scenarios.length)],
    ["Ticket coverage", `${data.summary.pendingTickets} pending / ${data.summary.resolvedTickets} resolved`],
  ]);

  renderSecurityTable(data.scenarios);
}

refreshAttemptsButton.addEventListener("click", async () => {
  await loadLoginAttempts();
});

resetAllAttemptsButton.addEventListener("click", async () => {
  try {
    await request("/admin/login-attempts/reset", {
      method: "POST",
      body: JSON.stringify({ scope: "all" }),
    });
    setMessage(loginAttemptMessage, "All tracked login attempts were reset.", "success");
    await Promise.all([loadOverview(), loadLoginAttempts()]);
  } catch (error) {
    setMessage(loginAttemptMessage, error.message, "error");
  }
});

securityCsvButton.addEventListener("click", async () => {
  try {
    await download(
      "/admin/security-report/export?format=csv",
      "webshield-security-report.csv"
    );
    setMessage(securityMessage, "Security report CSV export downloaded.", "success");
  } catch (error) {
    setMessage(securityMessage, error.message, "error");
  }
});

securityJsonButton.addEventListener("click", async () => {
  try {
    await download(
      "/admin/security-report/export?format=json",
      "webshield-security-report.json"
    );
    setMessage(securityMessage, "Security report JSON export downloaded.", "success");
  } catch (error) {
    setMessage(securityMessage, error.message, "error");
  }
});

logoutButton.addEventListener("click", async () => {
  await request("/auth/logout", { method: "POST" });
  window.location.href = "login.html";
});

async function initialiseAdminPage() {
  // Start the admin home page after access has been verified.
  try {
    await ensureAdminSession();
    setMessage(
      adminMessage,
      "Administrator session verified. Open users, moderation, or audit from the workspace buttons below.",
      "success"
    );
    await Promise.all([
      loadOverview(),
      loadLoginAttempts(),
      loadSecurityReport(),
    ]);
  } catch (error) {
    setMessage(adminMessage, error.message, "error");
    if (error.message === "This page is restricted to admin users.") {
      window.setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 1200);
    }
  }
}

initialiseAdminPage();
