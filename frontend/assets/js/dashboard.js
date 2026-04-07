// Script for the signed-in user dashboard.
// It combines account details, feedback history, feedback submission, and password changes.

import { request } from "./api.js?v=20260404d";
import {
  createStatusChip,
  formatDateTime,
  renderEmptyState,
  renderInfoRows,
  setMessage,
  toggleHidden,
} from "./ui.js?v=20260404d";

const userDetails = document.querySelector("#userDetails");
const feedbackList = document.querySelector("#feedbackList");
const feedbackForm = document.querySelector("#feedbackForm");
const formMessage = document.querySelector("#formMessage");
const logoutButton = document.querySelector("#logoutButton");
const adminLink = document.querySelector("#adminLink");
const auditLink = document.querySelector("#auditLink");
const dashboardMessage = document.querySelector("#dashboardMessage");
const passwordForm = document.querySelector("#passwordForm");
const passwordMessage = document.querySelector("#passwordMessage");

async function ensureSession() {
  // The dashboard only works for authenticated users, so this is the first check.
  const sessionData = await request("/auth/session");

  if (!sessionData.authenticated) {
    window.location.href = "login.html";
    throw new Error("Authentication required.");
  }

  renderInfoRows(userDetails, [
    ["Username", sessionData.user.username],
    ["Email", sessionData.user.email],
    ["Role", sessionData.user.role],
    ["Active", sessionData.user.isActive ? "Yes" : "No"],
    ["Last login", formatDateTime(sessionData.user.lastLoginAt)],
    [
      "Password updated",
      formatDateTime(sessionData.user.lastPasswordChangedAt),
    ],
  ]);

  const isAdmin = sessionData.user.role === "admin";
  toggleHidden(adminLink, !isAdmin);
  toggleHidden(auditLink, !isAdmin);
  setMessage(
    dashboardMessage,
    isAdmin
      ? "Administrator session active. You can review submissions in the admin dashboard and audit trail."
      : "Standard user session active. Admin routes remain restricted.",
    "success"
  );

  return sessionData.user;
}

function buildHistoryList(historyItems) {
  // Show the moderation timeline that comes from feedback status history rows.
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

function buildFeedbackCard(item) {
  // Render one feedback record exactly as it comes back from `/api/feedback/mine`.
  const article = document.createElement("article");
  article.className = "entry-card";

  const title = document.createElement("h3");
  title.textContent = item.title;

  const meta = document.createElement("p");
  meta.className = "entry-meta";
  meta.textContent =
    `Created: ${formatDateTime(item.createdAt)} | ` +
    `Updated: ${formatDateTime(item.updatedAt)}`;

  const message = document.createElement("p");
  message.textContent = item.message;

  article.append(title, createStatusChip(item.status), meta, message);

  if (item.adminNote) {
    const noteTitle = document.createElement("p");
    noteTitle.className = "section-label";
    noteTitle.textContent = "Admin note";

    const note = document.createElement("p");
    note.textContent = item.adminNote;
    article.append(noteTitle, note);
  }

  const history = buildHistoryList(item.history);
  if (history) {
    const historyTitle = document.createElement("p");
    historyTitle.className = "section-label";
    historyTitle.textContent = "Status history";
    article.append(historyTitle, history);
  }

  return article;
}

async function loadFeedback() {
  // Load the current user's own feedback records from the backend.
  const data = await request("/feedback/mine");

  if (!data.items.length) {
    renderEmptyState(
      feedbackList,
      "No feedback submitted yet. Use the form above to create your first record."
    );
    return;
  }

  feedbackList.innerHTML = "";
  data.items.forEach((item) => {
    feedbackList.append(buildFeedbackCard(item));
  });
}

feedbackForm.addEventListener("submit", async (event) => {
  // Create a new feedback item, then refresh the on-page list.
  event.preventDefault();
  setMessage(formMessage, "Submitting feedback...");

  try {
    const data = await request("/feedback/", {
      method: "POST",
      body: JSON.stringify({
        title: feedbackForm.title.value.trim(),
        message: feedbackForm.message.value.trim(),
      }),
    });

    feedbackForm.reset();
    setMessage(formMessage, data.message, "success");
    await loadFeedback();
  } catch (error) {
    setMessage(formMessage, error.message, "error");
  }
});

passwordForm.addEventListener("submit", async (event) => {
  // Change the signed-in user's password through the auth API.
  event.preventDefault();
  setMessage(passwordMessage, "Updating password...");

  try {
    await request("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({
        currentPassword: passwordForm.currentPassword.value,
        newPassword: passwordForm.newPassword.value,
        confirmPassword: passwordForm.confirmPassword.value,
      }),
    });

    passwordForm.reset();
    setMessage(passwordMessage, "Password changed successfully.", "success");
    await ensureSession();
  } catch (error) {
    setMessage(passwordMessage, error.message, "error");
  }
});

logoutButton.addEventListener("click", async () => {
  await request("/auth/logout", { method: "POST" });
  window.location.href = "login.html";
});

async function initialiseDashboard() {
  // Start the dashboard by confirming the session and then loading data.
  try {
    await ensureSession();
    await loadFeedback();
  } catch (error) {
    if (error.message !== "Authentication required.") {
      setMessage(formMessage, error.message, "error");
      setMessage(passwordMessage, error.message, "error");
    }
  }
}

initialiseDashboard();
