// Script for the dedicated moderation page.
// It keeps support-ticket review separate from user management and audit exports.

import { request } from "./api.js?v=20260408a";
import {
  createStatusChip,
  formatDateTime,
  renderEmptyState,
  renderInfoRows,
  setMessage,
} from "./ui.js?v=20260408a";

const adminInfo = document.querySelector("#adminInfo");
const adminMessage = document.querySelector("#adminMessage");
const moderationSummary = document.querySelector("#moderationSummary");
const ticketFilterForm = document.querySelector("#ticketFilterForm");
const adminTicketList = document.querySelector("#adminTicketList");
const ticketMessage = document.querySelector("#ticketMessage");
const logoutButton = document.querySelector("#logoutButton");

function formToParams(form) {
  // Convert the moderation filter form into URL query parameters.
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
  // This page is for administrators reviewing ticket activity.
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

function buildHistoryList(historyItems) {
  // Show the status timeline recorded for each support ticket.
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

function buildTicketCard(item) {
  // Render one support ticket plus the moderation controls for it.
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
  // This label text is static markup controlled by the app.
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
      await Promise.all([loadSummary(), loadAdminTickets()]);
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

async function loadSummary() {
  // Show the ticket-level headline counts relevant to moderation.
  const data = await request("/admin/overview");

  renderInfoRows(moderationSummary, [
    ["Support tickets", String(data.summary.totalTickets)],
    ["Pending tickets", String(data.summary.pendingTickets)],
    ["Reviewed tickets", String(data.summary.reviewedTickets)],
    ["Resolved tickets", String(data.summary.resolvedTickets)],
    ["Audit events", String(data.summary.auditEvents)],
    ["Lab mode", data.summary.labMode],
  ]);
}

async function loadAdminTickets() {
  // Load support tickets for review and status updates.
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

ticketFilterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadAdminTickets();
});

logoutButton.addEventListener("click", async () => {
  await request("/auth/logout", { method: "POST" });
  window.location.href = "login.html";
});

async function initialiseModerationPage() {
  // Verify the admin session and then load the moderation view.
  try {
    await ensureAdminSession();
    setMessage(
      adminMessage,
      "Administrator session verified. Use this page to review and update support tickets.",
      "success"
    );
    await Promise.all([loadSummary(), loadAdminTickets()]);
  } catch (error) {
    setMessage(adminMessage, error.message, "error");
    if (error.message === "This page is restricted to admin users.") {
      window.setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 1200);
    }
  }
}

initialiseModerationPage();
