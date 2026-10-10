"use strict";

function text(selector, value) {
  document.querySelector(selector).textContent = value;
}

function list(selector, values) {
  const root = document.querySelector(selector);
  root.replaceChildren();
  for (const value of values) {
    const row = document.createElement("li");
    row.textContent = value;
    root.appendChild(row);
  }
}

fetch("/api/v1/privacy", { credentials: "same-origin", headers: { Accept: "application/json" } })
  .then((response) => {
    if (!response.ok) throw new Error("Privacy details are unavailable.");
    return response.json();
  })
  .then((notice) => {
    text("#controller", notice.controller);
    text("#contact", notice.contact);
    text("#purpose", `Purpose: ${notice.purpose}`);
    text("#lawful-basis", `Legal basis: ${notice.lawful_basis}`);
    text("#processing-note", notice.processing_note);
    text("#retention", `Live items are retained for up to ${notice.retention_days} days. Encrypted backups may remain for up to ${notice.backup_retention_days} days after deletion.`);
    list("#categories", notice.data_categories);
    list("#rights", notice.rights);
  })
  .catch(() => text("#notice-error", "Privacy details couldn't be loaded. Check your internet connection and reload this page."));
