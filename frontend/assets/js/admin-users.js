// Script for the dedicated user-management page.
// It keeps account and role controls separate from moderation and audit browsing.

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
const userSummary = document.querySelector("#userSummary");
const userFilterForm = document.querySelector("#userFilterForm");
const userList = document.querySelector("#userList");
const userMessage = document.querySelector("#userMessage");
const logoutButton = document.querySelector("#logoutButton");
const userModal = document.querySelector("#userModal");
const closeUserModalButton = document.querySelector("#closeUserModalButton");
const userModalTitle = document.querySelector("#userModalTitle");
const userModalMessage = document.querySelector("#userModalMessage");
const selectedUserInfo = document.querySelector("#selectedUserInfo");
const modalRole = document.querySelector("#modalRole");
const modalActive = document.querySelector("#modalActive");
const updateUserButton = document.querySelector("#updateUserButton");
const resetPasswordInput = document.querySelector("#resetPasswordInput");
const resetPasswordConfirm = document.querySelector("#resetPasswordConfirm");
const resetPasswordButton = document.querySelector("#resetPasswordButton");
let currentAdminId = null;
let selectedUser = null;

function formToParams(form) {
  // Convert the user-filter form into URL query parameters.
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
  // This page is reserved for signed-in administrators.
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

function buildUserCard(user) {
  // Render one user record as a selectable profile summary.
  const article = document.createElement("article");
  article.className = "entry-card user-record-card";
  article.tabIndex = 0;
  article.setAttribute("role", "button");
  article.setAttribute("aria-label", `Open ${user.username} profile`);

  const title = document.createElement("h3");
  title.textContent = user.username;

  const meta = document.createElement("p");
  meta.className = "entry-meta";
  meta.textContent =
    `User ID: #${user.id} | Email: ${user.email}`;

  const counts = document.createElement("p");
  counts.textContent =
    `Role: ${user.role} | Status: ${user.isActive ? "active" : "disabled"} | ` +
    `Tickets: ${user.ticketCount} | Audit events: ${user.auditEventCount} | ` +
    `Last login: ${formatDateTime(user.lastLoginAt)}`;

  const hint = document.createElement("p");
  hint.className = "status-text user-card-hint";
  hint.textContent = "Click this profile to review identifiers and open edit controls.";

  article.addEventListener("click", () => {
    openUserModal(user);
  });

  article.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openUserModal(user);
    }
  });

  article.append(
    title,
    createStatusChip(user.role),
    createStatusChip(user.isActive ? "active" : "disabled"),
    meta,
    counts,
    hint
  );
  return article;
}

function renderSelectedUser() {
  // Populate the popup with the currently selected user's identifiers and controls.
  if (!selectedUser) {
    return;
  }

  userModalTitle.textContent = `${selectedUser.username} profile`;
  renderInfoRows(selectedUserInfo, [
    ["User ID", `#${selectedUser.id}`],
    ["Username", selectedUser.username],
    ["Email", selectedUser.email],
    ["Role", selectedUser.role],
    ["Account status", selectedUser.isActive ? "active" : "disabled"],
    ["Created", formatDateTime(selectedUser.createdAt)],
    ["Last login", formatDateTime(selectedUser.lastLoginAt)],
    ["Password updated", formatDateTime(selectedUser.lastPasswordChangedAt)],
    ["Tickets", String(selectedUser.ticketCount)],
    ["Audit events", String(selectedUser.auditEventCount)],
  ]);

  modalRole.value = selectedUser.role;
  modalActive.value = String(selectedUser.isActive);
  resetPasswordInput.value = "";
  resetPasswordConfirm.value = "";
  resetPasswordButton.disabled = selectedUser.id === currentAdminId;
  resetPasswordButton.title =
    selectedUser.id === currentAdminId
      ? "Use your own dashboard to change your own password."
      : "";
}

function openUserModal(user) {
  // Open the selected user's popup before any edits are made.
  selectedUser = { ...user };
  renderSelectedUser();
  setMessage(
    userModalMessage,
    "Review the profile details before applying any account changes.",
    "info"
  );
  userModal.classList.remove("hidden");
  userModal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
  closeUserModalButton.focus();
}

function closeUserModal() {
  // Hide the popup and reset the page-level focus state.
  userModal.classList.add("hidden");
  userModal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

async function loadSummary() {
  // Show the account-level headline counts relevant to user management.
  const data = await request("/admin/overview");

  renderInfoRows(userSummary, [
    ["Registered users", String(data.summary.totalUsers)],
    ["Active users", String(data.summary.activeUsers)],
    ["Disabled users", String(data.summary.disabledUsers)],
    ["Administrators", String(data.summary.adminUsers)],
    ["Audit events", String(data.summary.auditEvents)],
    ["Failed logins (24h)", String(data.summary.failedLoginsLast24h)],
  ]);
}

async function loadUsers() {
  // Load filtered users for the account-management list.
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

  if (selectedUser) {
    const refreshedUser = data.items.find((item) => item.id === selectedUser.id);
    if (refreshedUser) {
      selectedUser = { ...selectedUser, ...refreshedUser };
      renderSelectedUser();
    }
  }
}

userFilterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadUsers();
});

closeUserModalButton.addEventListener("click", closeUserModal);

userModal.addEventListener("click", (event) => {
  if (event.target === userModal) {
    closeUserModal();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !userModal.classList.contains("hidden")) {
    closeUserModal();
  }
});

updateUserButton.addEventListener("click", async () => {
  if (!selectedUser) {
    return;
  }

  try {
    const data = await request(`/admin/users/${selectedUser.id}`, {
      method: "PATCH",
      body: JSON.stringify({
        role: modalRole.value,
        isActive: modalActive.value === "true",
      }),
    });

    selectedUser = { ...selectedUser, ...data.user };
    setMessage(userMessage, `Updated ${selectedUser.username}.`, "success");
    setMessage(userModalMessage, data.message, "success");
    await Promise.all([loadSummary(), loadUsers()]);
  } catch (error) {
    setMessage(userMessage, error.message, "error");
    setMessage(userModalMessage, error.message, "error");
  }
});

resetPasswordButton.addEventListener("click", async () => {
  if (!selectedUser) {
    return;
  }

  try {
    const data = await request(`/admin/users/${selectedUser.id}/reset-password`, {
      method: "POST",
      body: JSON.stringify({
        newPassword: resetPasswordInput.value,
        confirmPassword: resetPasswordConfirm.value,
      }),
    });

    selectedUser = { ...selectedUser, ...data.user };
    setMessage(userMessage, `Password reset for ${selectedUser.username}.`, "success");
    setMessage(userModalMessage, data.message, "success");
    await Promise.all([loadSummary(), loadUsers()]);
  } catch (error) {
    setMessage(userMessage, error.message, "error");
    setMessage(userModalMessage, error.message, "error");
  }
});

logoutButton.addEventListener("click", async () => {
  await request("/auth/logout", { method: "POST" });
  window.location.href = "login.html";
});

async function initialiseUserManagementPage() {
  // Verify the admin session and then load the user-management view.
  try {
    await ensureAdminSession();
    setMessage(
      adminMessage,
      "Administrator session verified. Use this page to manage accounts and roles.",
      "success"
    );
    await Promise.all([loadSummary(), loadUsers()]);
  } catch (error) {
    setMessage(adminMessage, error.message, "error");
    if (error.message === "This page is restricted to admin users.") {
      window.setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 1200);
    }
  }
}

initialiseUserManagementPage();
