// Script for the demo lab page.
// This file intentionally uses unsafe rendering paths because the page is meant
// to demonstrate XSS, IDOR, and SQL injection behavior in demo mode only.

import { request } from "./api.js?v=20260408a";
import {
  formatDateTime,
  renderEmptyState,
  setMessage,
  toggleHidden,
} from "./ui.js?v=20260408a";

const modeMessage = document.querySelector("#modeMessage");
const adminLink = document.querySelector("#adminLink");
const auditLink = document.querySelector("#auditLink");
const reflectedForm = document.querySelector("#reflectedForm");
const reflectedStatus = document.querySelector("#reflectedStatus");
const reflectedPreview = document.querySelector("#reflectedPreview");
const lookupForm = document.querySelector("#lookupForm");
const lookupStatus = document.querySelector("#lookupStatus");
const lookupResult = document.querySelector("#lookupResult");
const searchForm = document.querySelector("#searchForm");
const searchStatus = document.querySelector("#searchStatus");
const searchResult = document.querySelector("#searchResult");

async function syncAdminNavigation() {
  // Show admin links only when the current session belongs to an administrator.
  try {
    const sessionData = await request("/auth/session");
    const isAdmin =
      sessionData.authenticated && sessionData.user.role === "admin";
    toggleHidden(adminLink, !isAdmin);
    toggleHidden(auditLink, !isAdmin);
  } catch {
    toggleHidden(adminLink, true);
    toggleHidden(auditLink, true);
  }
}

async function loadStatus() {
  // Let the user know whether the backend has demo mode enabled.
  const data = await request("/lab/status");
  setMessage(
    modeMessage,
    data.demoEnabled
      ? "Demo mode is enabled. These routes are intentionally insecure and must stay local."
      : "Demo mode is disabled. Set LAB_MODE=demo in backend/.env and restart the backend to unlock the lab routes.",
    data.demoEnabled ? "error" : "success"
  );
}

reflectedForm.addEventListener("submit", async (event) => {
  // This route returns raw HTML on purpose, so `innerHTML` is part of the demo.
  event.preventDefault();
  setMessage(reflectedStatus, "Rendering unsafe preview...");

  try {
    const data = await request("/lab/echo-preview", {
      method: "POST",
      body: JSON.stringify({ content: reflectedForm.content.value }),
    });
    reflectedPreview.innerHTML = data.unsafeHtml;
    setMessage(reflectedStatus, data.message, "success");
  } catch (error) {
    reflectedPreview.innerHTML = "";
    setMessage(reflectedStatus, error.message, "error");
  }
});

lookupForm.addEventListener("submit", async (event) => {
  // This card shows what an insecure object lookup can reveal.
  event.preventDefault();
  setMessage(lookupStatus, "Looking up a support ticket without object-level checks...");

  try {
    const data = await request(
      `/lab/public-tickets/${encodeURIComponent(lookupForm.ticketId.value)}`
    );
    lookupResult.innerHTML = `
      <article class="entry-card">
        <h3>${data.ticket.title}</h3>
        <p class="entry-meta">Author: ${data.ticket.author.username} | Created: ${formatDateTime(
          data.ticket.createdAt
        )}</p>
        <p>${data.ticket.message}</p>
      </article>
    `;
    setMessage(lookupStatus, data.warning, "success");
  } catch (error) {
    lookupResult.innerHTML = "";
    setMessage(lookupStatus, error.message, "error");
  }
});

searchForm.addEventListener("submit", async (event) => {
  // This sends a crafted search term to the intentionally unsafe SQL route.
  event.preventDefault();
  setMessage(searchStatus, "Executing intentionally unsafe SQL search...");

  try {
    const query = encodeURIComponent(searchForm.title.value.trim());
    const data = await request(`/lab/insecure-search?title=${query}`);
    if (!data.rows.length) {
      renderEmptyState(searchResult, "The vulnerable search route returned no rows.");
    } else {
      searchResult.innerHTML = `
        <article class="entry-card">
          <h3>Unsafe query</h3>
          <p class="entry-meta mono">${data.query}</p>
          <p>${data.warning}</p>
          <div class="entry-list">
            ${data.rows
              .map(
                (row) =>
                  `<div class="entry-card"><strong>${row.title}</strong><p class="entry-meta">Ticket #${row.id} | Status: ${row.status} | User: ${row.user_id}</p></div>`
              )
              .join("")}
          </div>
        </article>
      `;
    }
    setMessage(searchStatus, data.warning, "success");
  } catch (error) {
    searchResult.innerHTML = "";
    setMessage(searchStatus, error.message, "error");
  }
});

syncAdminNavigation();

loadStatus().catch((error) => {
  setMessage(modeMessage, error.message, "error");
});
