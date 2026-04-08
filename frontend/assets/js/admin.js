// Script for the main admin dashboard.
// It ties together user management, ticket review, login-attempt review,
// audit browsing, and security-report exports.

import { download, request } from "./api.js?v=20260408a";
import {
  createStatusChip,
  formatDateTime,
  getAuditThreatMeta,
  renderEmptyState,
  renderInfoRows,
  setMessage,
} from "./ui.js?v=20260408a";

const adminInfo = document.querySelector("#adminInfo");
const adminMessage = document.querySelector("#adminMessage");
const adminOverview = document.querySelector("#adminOverview");
const userFilterForm = document.querySelector("#userFilterForm");
const userList = document.querySelector("#userList");
const userMessage = document.querySelector("#userMessage");
const loginAttemptList = document.querySelector("#loginAttemptList");
const loginAttemptMessage = document.querySelector("#loginAttemptMessage");
const refreshAttemptsButton = document.querySelector("#refreshAttemptsButton");
const resetAllAttemptsButton = document.querySelector("#resetAllAttemptsButton");
const ticketFilterForm = document.querySelector("#ticketFilterForm");
const adminTicketList = document.querySelector("#adminTicketList");
const ticketMessage = document.querySelector("#ticketMessage");
const auditFilterForm = document.querySelector("#auditFilterForm");
const auditLogList = document.querySelector("#auditLogList");
const auditMessage = document.querySelector("#auditMessage");
const auditCsvButton = document.querySelector("#auditCsvButton");
const auditJsonButton = document.querySelector("#auditJsonButton");
const securitySummary = document.querySelector("#securitySummary");
const securityTableBody = document.querySelector("#securityTableBody");
const securityMessage = document.querySelector("#securityMessage");
const securityCsvButton = document.querySelector("#securityCsvButton");
const securityJsonButton = document.querySelector("#securityJsonButton");
const logoutButton = document.querySelector("#logoutButton");
let currentAdminId = null;

function formToParams(form) {
  // Convert a filter form into query parameters for admin API requests.
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

  currentAdminId = sessionData.user.id;
  return sessionData.user;
}

function buildHistoryList(historyItems) {
  // Reuse the same status-history rendering for support ticket moderation cards.
  if (!historyItems?.length) {
    return null;
  }

  const wrapper = document.createElement("div");
  wrapper.className = "history-list";

  historyItems.forEach((item) => {
    const block = document.createElement("div");
    block.className = "history-item";

    const title = document.createElement("strong");
    title.textContent = `${item.previousStatus || "new"} -> ${item.nextStatus}`;

    const meta = document.createElement("p");
    meta.className = "entry-meta";
    meta.textContent =
      `By: ${item.actor?.username || "system"} | ` +
      `At: ${formatDateTime(item.createdAt)}`;

    block.append(title, meta);
    if (item.note) {
      const note = document.createElement("p");
      note.textContent = item.note;
      block.append(note);
    }

    wrapper.append(block);
  });

  return wrapper;
}

function buildUserCard(user) {
  // Render one user record with admin controls for role, status, and password reset.
  const article = document.createElement("article");
  article.className = "entry-card";

  const title = document.createElement("h3");
  title.textContent = user.username;

  const meta = document.createElement("p");
  meta.className = "entry-meta";
  meta.textContent =
    `${user.email} | Created: ${formatDateTime(user.createdAt)} | ` +
    `Last login: ${formatDateTime(user.lastLoginAt)}`;

  const counts = document.createElement("p");
  counts.textContent =
    `Tickets: ${user.ticketCount} | Audit events: ${user.auditEventCount} | ` +
    `Password updated: ${formatDateTime(user.lastPasswordChangedAt)}`;

  const controls = document.createElement("div");
  controls.className = "admin-controls";

  const roleSelect = document.createElement("select");
  ["user", "admin"].forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    option.selected = value === user.role;
    roleSelect.append(option);
  });

  const activeSelect = document.createElement("select");
  [
    { value: "true", label: "active" },
    { value: "false", label: "disabled" },
  ].forEach((entry) => {
    const option = document.createElement("option");
    option.value = entry.value;
    option.textContent = entry.label;
    option.selected = String(user.isActive) === entry.value;
    activeSelect.append(option);
  });

  const updateButton = document.createElement("button");
  updateButton.type = "button";
  updateButton.textContent = "Update User";
  updateButton.addEventListener("click", async () => {
    try {
      await request(`/admin/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          role: roleSelect.value,
          isActive: activeSelect.value === "true",
        }),
      });
      setMessage(userMessage, `Updated ${user.username}.`, "success");
      await Promise.all([loadOverview(), loadUsers(), loadAuditLogs()]);
    } catch (error) {
      setMessage(userMessage, error.message, "error");
    }
  });

  controls.append(roleSelect, activeSelect, updateButton);

  const passwordLabel = document.createElement("label");
  passwordLabel.className = "stacked-form";
  // This HTML is static markup written by the app itself, not user data.
  passwordLabel.innerHTML = "<span>Admin reset password</span>";

  const passwordInput = document.createElement("input");
  passwordInput.type = "password";
  passwordInput.placeholder = "New password";
  passwordInput.minLength = 10;

  const confirmInput = document.createElement("input");
  confirmInput.type = "password";
  confirmInput.placeholder = "Confirm new password";
  confirmInput.minLength = 10;

  passwordLabel.append(passwordInput, confirmInput);

  const resetButton = document.createElement("button");
  resetButton.type = "button";
  resetButton.textContent = "Reset Password";
  resetButton.disabled = user.id === currentAdminId;
  resetButton.title =
    user.id === currentAdminId
      ? "Use your own dashboard to change your own password."
      : "";
  resetButton.addEventListener("click", async () => {
    try {
      await request(`/admin/users/${user.id}/reset-password`, {
        method: "POST",
        body: JSON.stringify({
          newPassword: passwordInput.value,
          confirmPassword: confirmInput.value,
        }),
      });
      passwordInput.value = "";
      confirmInput.value = "";
      setMessage(userMessage, `Password reset for ${user.username}.`, "success");
      await Promise.all([loadUsers(), loadAuditLogs()]);
    } catch (error) {
      setMessage(userMessage, error.message, "error");
    }
  });

  controls.append(passwordLabel, resetButton);

  article.append(
    title,
    createStatusChip(user.role),
    createStatusChip(user.isActive ? "active" : "disabled"),
    meta,
    counts,
    controls
  );
  return article;
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

function buildTicketCard(item) {
  // Render one support ticket plus the admin controls that can change it.
  const article = document.createElement("article");
  article.className = "entry-card";

  const title = document.createElement("h3");
  title.textContent = item.title;

  const meta = document.createElement("p");
  meta.className = "entry-meta";
  meta.textContent =
    `Author: ${item.author.username} (${item.author.email}) | ` +
    `Created: ${formatDateTime(item.createdAt)} | ` +
    `Updated: ${formatDateTime(item.updatedAt)}`;

  const message = document.createElement("p");
  message.textContent = item.message;

  const noteLabel = document.createElement("label");
  noteLabel.className = "stacked-form";
  // This label text is fixed by the app, so `innerHTML` is only used for layout.
  noteLabel.innerHTML = "<span>Admin note</span>";
  const noteInput = document.createElement("textarea");
  noteInput.rows = 3;
  noteInput.value = item.adminNote || "";
  noteLabel.append(noteInput);

  const controls = document.createElement("div");
  controls.className = "admin-controls";

  const select = document.createElement("select");
  ["pending", "reviewed", "resolved"].forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    option.selected = value === item.status;
    select.append(option);
  });

  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Update Ticket";
  button.addEventListener("click", async () => {
    try {
      await request(`/admin/tickets/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          status: select.value,
          adminNote: noteInput.value.trim(),
        }),
      });
      setMessage(ticketMessage, "Support ticket updated successfully.", "success");
      await Promise.all([loadOverview(), loadAdminTickets(), loadAuditLogs()]);
    } catch (error) {
      setMessage(ticketMessage, error.message, "error");
    }
  });

  controls.append(select, button);

  article.append(title, createStatusChip(item.status), meta, message, noteLabel, controls);

  const history = buildHistoryList(item.history);
  if (history) {
    const historyTitle = document.createElement("p");
    historyTitle.className = "section-label";
    historyTitle.textContent = "Status history";
    article.append(historyTitle, history);
  }

  return article;
}

function buildAuditCard(item) {
  // Render one audit entry using the shared severity mapping from `ui.js`.
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

async function loadUsers() {
  // Load filtered users for the account-management area.
  const params = formToParams(userFilterForm);
  const query = params.toString();
  const data = await request(`/admin/users${query ? `?${query}` : ""}`);

  if (!data.items.length) {
    renderEmptyState(userList, "No users match the current filters.");
    return;
  }

  userList.innerHTML = "";
  data.items.forEach((item) => {
    userList.append(buildUserCard(item));
  });
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

async function loadAdminTickets() {
  // Load support tickets for moderation and status changes.
  const params = formToParams(ticketFilterForm);
  const query = params.toString();
  const data = await request(`/admin/tickets${query ? `?${query}` : ""}`);

  if (!data.items.length) {
    renderEmptyState(adminTicketList, "No support tickets are available yet.");
    return;
  }

  adminTicketList.innerHTML = "";
  data.items.forEach((item) => {
    adminTicketList.append(buildTicketCard(item));
  });
}

async function loadAuditLogs() {
  // Load audit records using the current audit filter controls.
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

// Form submissions refresh only the part of the dashboard they control.
userFilterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadUsers();
});

ticketFilterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAdminTickets();
});

auditFilterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAuditLogs();
});

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
    await Promise.all([loadOverview(), loadLoginAttempts(), loadAuditLogs()]);
  } catch (error) {
    setMessage(loginAttemptMessage, error.message, "error");
  }
});

// Export buttons call dedicated backend download endpoints.
auditCsvButton.addEventListener("click", async () => {
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
  // Start the full admin dashboard after access has been verified.
  try {
    await ensureAdminSession();
    setMessage(adminMessage, "Administrator session verified.", "success");
    await Promise.all([
      loadOverview(),
      loadUsers(),
      loadLoginAttempts(),
      loadAdminTickets(),
      loadAuditLogs(),
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
