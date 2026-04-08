// Shared responsive navigation toggle used across the frontend pages.

const mobileMedia = window.matchMedia("(max-width: 720px)");

function setExpanded(button, nav, expanded) {
  // Keep the button state and the nav visibility in sync.
  nav.classList.toggle("is-open", expanded);
  button.setAttribute("aria-expanded", expanded ? "true" : "false");
  button.textContent = expanded ? "Close" : "Menu";
}

document.querySelectorAll(".topbar").forEach((topbar, index) => {
  const button = topbar.querySelector(".nav-toggle");
  const nav = topbar.querySelector(".nav");

  if (!button || !nav) {
    return;
  }

  if (!nav.id) {
    nav.id = `site-nav-${index + 1}`;
  }

  button.setAttribute("aria-controls", nav.id);
  setExpanded(button, nav, false);

  button.addEventListener("click", () => {
    setExpanded(button, nav, !nav.classList.contains("is-open"));
  });

  nav.querySelectorAll("a, button").forEach((control) => {
    control.addEventListener("click", () => {
      if (mobileMedia.matches) {
        setExpanded(button, nav, false);
      }
    });
  });

  const handleViewportChange = (event) => {
    if (!event.matches) {
      setExpanded(button, nav, false);
    }
  };

  if (typeof mobileMedia.addEventListener === "function") {
    mobileMedia.addEventListener("change", handleViewportChange);
  } else {
    mobileMedia.addListener(handleViewportChange);
  }
});
