// Script for the registration page.
// It creates new accounts and redirects people away if they are already signed in.

import { request } from "./api.js?v=20260404d";
import { setMessage } from "./ui.js?v=20260404d";

const form = document.querySelector("#registerForm");
const messageBox = document.querySelector("#message");

function authenticatedRedirect(user) {
  // Signed-in users should go back to their real landing page, not stay here.
  window.location.replace(user.role === "admin" ? "admin.html" : "dashboard.html");
}

async function ensureGuestSession() {
  // This keeps the register page for guests only.
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

async function initialiseRegisterPage() {
  // Attach the submit behavior only when the user is not already authenticated.
  const canShowForm = await ensureGuestSession();
  if (!canShowForm) {
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage(messageBox, "Creating account...");

    const payload = {
      username: form.username.value.trim(),
      email: form.email.value.trim(),
      password: form.password.value,
    };

    try {
      const data = await request("/auth/register", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      form.reset();
      setMessage(
        messageBox,
        `${data.message} You can now sign in with your new account.`,
        "success"
      );
    } catch (error) {
      setMessage(messageBox, error.message, "error");
    }
  });
}

initialiseRegisterPage();
