// Keep local development on one loopback hostname so cookies and sessions stay consistent.

const loopbackHosts = new Set(["0.0.0.0", "::1", "localhost"]);

if (loopbackHosts.has(window.location.hostname)) {
  const canonicalUrl = new URL(window.location.href);
  canonicalUrl.hostname = "127.0.0.1";
  window.location.replace(canonicalUrl.toString());
}
