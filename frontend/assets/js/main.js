// Script for the public landing page.
// It reads session state and lab mode so the homepage shows the right actions.

import { request } from "./api.js?v=20260404d";
import { setMessage, toggleHidden } from "./ui.js?v=20260404d";

const sessionStatus = document.querySelector("#sessionStatus");
const labStatus = document.querySelector("#labStatus");
const registerNavLink = document.querySelector("#registerNavLink");
const loginNavLink = document.querySelector("#loginNavLink");
const adminNavLink = document.querySelector("#adminNavLink");
const auditNavLink = document.querySelector("#auditNavLink");
const logoutNavButton = document.querySelector("#logoutNavButton");
const createAccountLink = document.querySelector("#createAccountLink");
const signInLink = document.querySelector("#signInLink");
const logoutHeroButton = document.querySelector("#logoutHeroButton");
const registerRouteCard = document.querySelector("#registerRouteCard");
const loginRouteCard = document.querySelector("#loginRouteCard");
const adminRouteCard = document.querySelector("#adminRouteCard");
const auditRouteCard = document.querySelector("#auditRouteCard");
const sessionHeadline = document.querySelector("#sessionHeadline");
const labHeadline = document.querySelector("#labHeadline");
const identityValue = document.querySelector("#identityValue");
const roleValue = document.querySelector("#roleValue");
const adminValue = document.querySelector("#adminValue");
const routeValue = document.querySelector("#routeValue");
const modeValue = document.querySelector("#modeValue");
const nextStep = document.querySelector("#nextStep");

function setText(element, value) {
  // Small guard so repeated text updates do not need null checks everywhere.
  if (!element) {
    return;
  }

  element.textContent = value;
}

function toggleSessionActions(isAuthenticated) {
  // Guest actions and signed-in actions should never show at the same time.
  toggleHidden(registerNavLink, isAuthenticated);
  toggleHidden(loginNavLink, isAuthenticated);
  toggleHidden(logoutNavButton, !isAuthenticated);
  toggleHidden(createAccountLink, isAuthenticated);
  toggleHidden(signInLink, isAuthenticated);
  toggleHidden(logoutHeroButton, !isAuthenticated);
  toggleHidden(registerRouteCard, isAuthenticated);
  toggleHidden(loginRouteCard, isAuthenticated);
}

async function handleLogout() {
  // The homepage can end the session without needing a separate page.
  try {
    await request("/auth/logout", { method: "POST" });
  } finally {
    window.location.href = "login.html";
  }
}

logoutNavButton?.addEventListener("click", handleLogout);
logoutHeroButton?.addEventListener("click", handleLogout);

async function loadOverview() {
  // Read both the session endpoint and the lab-status endpoint in one place
  // because the landing page reacts to both pieces of backend state.
  try {
    const [sessionData, labData] = await Promise.all([
      request("/auth/session"),
      request("/lab/status"),
    ]);

    const isAdmin =
      sessionData.authenticated && sessionData.user.role === "admin";
    toggleSessionActions(sessionData.authenticated);
    toggleHidden(adminNavLink, !isAdmin);
    toggleHidden(auditNavLink, !isAdmin);
    toggleHidden(adminRouteCard, !isAdmin);
    toggleHidden(auditRouteCard, !isAdmin);

    setText(modeValue, labData.demoEnabled ? "Demo mode" : "Secure mode");
    if (modeValue) {
      modeValue.classList.remove("status-info", "status-active", "status-critical");
      modeValue.classList.add(
        labData.demoEnabled ? "status-critical" : "status-active"
      );
    }
    setText(labHeadline, labData.demoEnabled ? "Demo routes are live." : "Secure routes are active.");

    if (sessionData.authenticated) {
      setText(sessionHeadline, `Signed in as ${sessionData.user.username}`);
      setText(identityValue, sessionData.user.username);
      setText(roleValue, sessionData.user.role);
      setText(adminValue, isAdmin ? "Visible" : "Hidden");
      setText(routeValue, isAdmin ? "Admin / Audit" : "Dashboard");
      setText(
        nextStep,
        isAdmin
          ? "Open the admin or audit views to inspect moderation changes, account controls, and the evidence trail."
          : "Head to the dashboard, submit or review feedback, and compare what the normal user flow records."
      );
      setMessage(
        sessionStatus,
        `Signed in as ${sessionData.user.username} with ${sessionData.user.role} permissions.`,
        "success"
      );
    } else {
      setText(sessionHeadline, "Guest session detected.");
      setText(identityValue, "Guest");
      setText(roleValue, "visitor");
      setText(adminValue, "Locked");
      setText(routeValue, "Register / Login");
      setText(
        nextStep,
        "Create a standard account first. That gives you a realistic baseline for session handling, feedback submission, and later admin review."
      );
      setMessage(
        sessionStatus,
        "No active session yet. Register or sign in to begin the normal workflow.",
        "info"
      );
    }

    setMessage(
      labStatus,
      labData.demoEnabled
        ? "Demo mode is enabled. Keep those routes limited to local, intentional testing."
        : "Secure mode is active. The vulnerable lab routes stay unavailable until LAB_MODE is set to demo.",
      labData.demoEnabled ? "error" : "success"
    );
  } catch (error) {
    toggleSessionActions(false);
    setText(sessionHeadline, "Unable to read session state.");
    setText(labHeadline, "Unable to read environment state.");
    setText(identityValue, "Unavailable");
    setText(roleValue, "Unavailable");
    setText(adminValue, "Unavailable");
    setText(routeValue, "Unavailable");
    setText(modeValue, "Unavailable");
    setText(
      nextStep,
      "The homepage could not load its status data. Check that the backend is running and reachable from this page."
    );
    setMessage(sessionStatus, error.message, "error");
    setMessage(labStatus, error.message, "error");
  }
}

loadOverview();
