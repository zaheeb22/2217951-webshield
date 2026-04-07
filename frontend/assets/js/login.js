// Script for the login page.
// It keeps signed-in users away from guest-only forms and sends login requests.

import { request } from "./api.js?v=20260404d";
import { setMessage } from "./ui.js?v=20260404d";

const form = document.querySelector("#loginForm");
const messageBox = document.querySelector("#message");

function authenticatedRedirect(user) {
  // Send admins to the admin area and normal users to their dashboard.
  window.location.replace(user.role === "admin" ? "admin.html" : "dashboard.html");
}

async function ensureGuestSession() {
  // If a session already exists, this page should not keep showing the login form.
  try {
    const sessionData = await request("/auth/session");
    if (sessionData.authenticated) {
      authenticatedRedirect(sessionData.user);
      return false;
    }
  } catch {
    return true;
  }

  return true;
}

async function initialiseLoginPage() {
  // Wire up the form only after confirming this page is being used by a guest.
  const canShowForm = await ensureGuestSession();
  if (!canShowForm) {
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage(messageBox, "Authenticating...");

    const payload = {
      email: form.email.value.trim(),
      password: form.password.value,
    };

    try {
      const data = await request("/auth/login", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      setMessage(messageBox, "Login successful. Redirecting...", "success");
      window.setTimeout(() => {
        authenticatedRedirect(data.user);
      }, 700);
    } catch (error) {
      setMessage(messageBox, error.message, "error");
    }
  });
}

initialiseLoginPage();
