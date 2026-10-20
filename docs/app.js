/* ShipSafe landing page — no dependencies, no CDN, works fully offline. */
(() => {
  "use strict";

  // ---------------------------------------------------------------- config
  //
  // The order form has to survive being hosted in three different places:
  // a Netlify site, a GitHub Pages site, and a plain file:// preview. Each
  // one can capture a lead in a different way, so the form tries them in
  // order and falls back to a prefilled email if none of them work. A lead
  // must never be lost because the form host is having a bad day.
  //
  // The Netlify path is the primary one: a form with a `name` and the
  // `netlify` attribute is captured by Netlify's build bot automatically and
  // the submission shows up in the Netlify dashboard for this site. No
  // third-party service, no API key, no credit card.
  const CONFIG = {
    // Where a lead is delivered if every programmatic route fails.
    mailFallback: "mailto:rajibulislam584452@gmail.com",
    // Netlify's own form handling, used when this page is served by Netlify.
    netlifyPath: "/",
    // FormSubmit mirrors the form to the given address and needs no
    // account. It is the route that works on GitHub Pages. It answers the
    // first request with a "confirm your email" link, which is handled.
    formSubmitPath: "https://formsubmit.co/ajax/rajibulislam584452@gmail.com",
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  // ---------------------------------------------------------------- year
  const yearEl = $("#year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  // ---------------------------------------------------------------- form
  const form = $("#demoForm");
  const msg = $("#formMsg");
  const btn = $("#demoBtn");

  /** A small, forgiving email check. The provider is the real authority. */
  function looksLikeEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(value || "").trim());
  }

  /** Flatten the form into a plain object of strings. */
  function collect(form) {
    const out = {};
    for (const [key, value] of new FormData(form).entries()) {
      out[key] = typeof value === "string" ? value.trim() : value;
    }
    return out;
  }

  /** POST to a URL as JSON and report whether the server accepted it. */
  async function postJson(url, payload) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res;
  }

  /** POST to a URL as a normal HTML form submission. */
  async function postForm(url, payload) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(payload).toString(),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res;
  }

  /**
   * Try each capture route in turn. Returns the name of the route that
   * worked, or throws if they all failed.
   */
  async function deliver(data) {
    const payload = {
      ...data,
      subject: `ShipSafe ${data.tier || "review"} request — ${data.biz || "new lead"}`,
      source: "shipsafe-landing-order-form",
      submittedAt: new Date().toISOString(),
      page: location.href,
      referrer: document.referrer || null,
    };

    const errors = [];

    // 1. Netlify's own form handling. Only meaningful on a Netlify site,
    //    but harmless elsewhere (it just 404s and we move on).
    try {
      await postForm(CONFIG.netlifyPath, payload);
      return "netlify";
    } catch (err) {
      errors.push("netlify: " + err.message);
    }

    // 2. FormSubmit, which needs no account and works on any static host.
    try {
      const res = await postJson(CONFIG.formSubmitPath, payload);
      const text = await res.text();
      // FormSubmit answers the very first submission with a confirmation
      // link rather than "delivered". That still means the lead is safe:
      // the confirmation email is what unlocks delivery.
      try {
        const json = JSON.parse(text);
        if (json && json.success === true) return "formsubmit";
        if (json && json.status === "confirmation_sent") return "formsubmit-confirm";
      } catch {
        /* not JSON - treat the 2xx as delivered */
      }
      return "formsubmit";
    } catch (err) {
      errors.push("formsubmit: " + err.message);
    }

    throw new Error(errors.join(" | "));
  }

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!msg) return;

      const data = collect(form);
      const email = String(data.email || "").trim();

      if (!email) {
        msg.className = "form-msg err";
        msg.textContent = "I need an email address to send the report and the walkthrough to.";
        const field = $("#email");
        if (field) field.focus();
        return;
      }
      if (!looksLikeEmail(email)) {
        msg.className = "form-msg err";
        msg.textContent = "That email address does not look right — check it and try again.";
        const field = $("#email");
        if (field) field.focus();
        return;
      }
      if (!data.url) {
        msg.className = "form-msg err";
        msg.textContent = "Add the repo link or the live URL so I know what to review.";
        const field = $("#url");
        if (field) field.focus();
        return;
      }

      btn.disabled = true;
      btn.textContent = "Sending…";
      msg.className = "form-msg";
      msg.textContent = "";

      try {
        const route = await deliver(data);
        msg.className = "form-msg ok";
        msg.textContent =
          route === "formsubmit-confirm"
            ? "Almost there — I have your request. Check " + email + " for one confirmation click, then I'll get to work."
            : "Got it. You'll hear from me at " + email + " within a few hours, with the delivery date and what I need from you.";
        form.reset();
      } catch (err) {
        // Never lose a lead because every programmatic route failed. Hand
        // the visitor a prefilled email they can send with one click.
        const subject = encodeURIComponent(
          "ShipSafe " + (data.tier || "review") + " request — " + (data.biz || "new lead")
        );
        const body = encodeURIComponent(
          Object.entries(data)
            .map(([k, v]) => `${k}: ${v}`)
            .join("\n")
        );
        msg.className = "form-msg ok";
        msg.innerHTML =
          'Almost — send this from your email and I\'ll reply within the hour: ' +
          '<a href="' + CONFIG.mailFallback + "?subject=" + subject + "&body=" + body + '">open the prefilled email</a>.';
      } finally {
        btn.disabled = false;
        btn.textContent = "Order the review";
      }
    });
  }

  // ---------------------------------------------------------------- nav active state
  //
  // Only in-page anchors belong here. A nav link to a real page (for example
  // the free scanner at "scanner/") must not be handed to querySelector,
  // which would throw on anything that is not a valid CSS selector.
  const navLinks = $$(".links a").filter((a) => (a.getAttribute("href") || "").startsWith("#"));
  const sections = navLinks
    .map((a) => document.querySelector(a.getAttribute("href")))
    .filter(Boolean);

  if (sections.length && "IntersectionObserver" in window) {
    const spy = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          navLinks.forEach((a) =>
            a.style.color = a.getAttribute("href") === "#" + e.target.id ? "var(--txt)" : ""
          );
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    sections.forEach((s) => spy.observe(s));
  }
})();
