// Small UI helpers shared by the page-specific scripts.

function setMessage(element, message, type = "info") {
  // Show one short status message and color it by type.
  if (!element) {
    return;
  }

  element.textContent = message;
  element.classList.remove("is-success", "is-error");

  if (type === "success") {
    element.classList.add("is-success");
  } else if (type === "error") {
    element.classList.add("is-error");
  }
}

function toggleHidden(element, shouldHide) {
  // Reuse the same hide/show rule across all pages.
  if (!element) {
    return;
  }

  element.classList.toggle("hidden", shouldHide);
}

function formatDateTime(value) {
  // Turn ISO timestamps from the API into something easier to read.
  if (!value) {
    return "Unknown";
  }

  return new Date(value).toLocaleString();
}

function createStatusChip(label) {
  // Build a small badge used for roles, statuses, and severity labels.
  const chip = document.createElement("span");
  chip.className = `status-chip status-${String(label).toLowerCase()}`;
  chip.textContent = label;
  return chip;
}

function getAuditThreatMeta(action, targetType = "") {
  // Group raw audit actions into simple severity buckets for the UI.
  const normalizedAction = String(action || "").toLowerCase();
  const normalizedTargetType = String(targetType || "").toLowerCase();

  if (normalizedAction.startsWith("lab_") || normalizedTargetType === "lab") {
    return {
      level: "critical",
      label: "critical",
      description: "Intentional vulnerable lab activity",
    };
  }

  if (
    [
      "login_failed",
      "admin_access_denied",
      "login_blocked_inactive_account",
    ].includes(normalizedAction)
  ) {
    return {
      level: "high",
      label: "high",
      description: "Potential unauthorized access or blocked login activity",
    };
  }

  if (
    [
      "password_reset_by_admin",
      "user_updated",
      "login_attempts_reset",
    ].includes(normalizedAction)
  ) {
    return {
      level: "medium",
      label: "medium",
      description: "Sensitive administrative change",
    };
  }

  if (
    [
      "password_changed",
      "feedback_updated",
    ].includes(normalizedAction)
  ) {
    return {
      level: "low",
      label: "low",
      description: "Authenticated security or workflow update",
    };
  }

  return {
    level: "info",
    label: "info",
    description: "Routine application activity",
  };
}

function renderInfoRows(container, rows) {
  // Render label/value pairs used in summary panels and account details.
  container.innerHTML = "";
  rows.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "info-row";

    const left = document.createElement("span");
    left.textContent = label;

    const right = document.createElement("strong");
    right.textContent = value;

    row.append(left, right);
    container.append(row);
  });
}

function renderEmptyState(container, message) {
  // Reuse the same empty-state block when an API list comes back empty.
  container.innerHTML = "";
  const block = document.createElement("div");
  block.className = "empty-state";
  block.textContent = message;
  container.append(block);
}

export {
  createStatusChip,
  formatDateTime,
  getAuditThreatMeta,
  renderEmptyState,
  renderInfoRows,
  setMessage,
  toggleHidden,
};
