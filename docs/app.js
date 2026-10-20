/* CallLoop landing page — no dependencies, no CDN, works fully offline. */
(() => {
  "use strict";

  // ---------------------------------------------------------------- config
  // Where demo requests are POSTed. Point this at the CallLoop API once deployed.
  const CONFIG = {
    demoEndpoint: window.CALLLOOP_DEMO_ENDPOINT || "/api/public/demo-lead",
    mailFallback: "mailto:hello@callloop.app",
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  // ---------------------------------------------------------------- year
  const yearEl = $("#year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  // ---------------------------------------------------------------- ROI calculator
  const calls = $("#calls");
  const value = $("#value");
  const rate = $("#rate");
  const MONTHLY_PRICE = 79; // Growth plan, the one the ROI is compared against

  const money = (n) =>
    "$" + n.toLocaleString("en-US", { maximumFractionDigits: 0 });

  function updateRoi() {
    if (!calls || !value || !rate) return;
    const callsPerWeek = Number(calls.value);
    const jobValue = Number(value.value);
    const recoverRate = Number(rate.value) / 100;

    $("#callsOut").textContent = String(callsPerWeek);
    $("#valueOut").textContent = money(jobValue);
    $("#rateOut").textContent = Math.round(recoverRate * 100) + "%";

    const monthlyCalls = callsPerWeek * 4.33;
    const jobs = Math.round(monthlyCalls * recoverRate);
    const revenue = jobs * jobValue;
    const net = revenue - MONTHLY_PRICE;

    $("#jobs").textContent = String(jobs);
    $("#rev").textContent = money(revenue);
    $("#cost").textContent = money(MONTHLY_PRICE);
    $("#net").textContent = money(net);

    const lost = Math.round(monthlyCalls * jobValue);
    const note = $("#roiNote");
    if (note) {
      note.innerHTML =
        "Your business loses an estimated <b>" + money(lost) +
        "</b> a month to missed calls. CallLoop costs less than a single job.";
    }
  }

  [calls, value, rate].forEach((el) => {
    if (el) el.addEventListener("input", updateRoi);
  });
  updateRoi();

  // ---------------------------------------------------------------- chat animation
  // Replays the demo conversation when it scrolls into view. Respects
  // prefers-reduced-motion by simply revealing everything at once.
  const chatBody = $("#chatBody");
  if (chatBody) {
    const bubbles = $$(".bubble", chatBody);
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reduced) {
      bubbles.forEach((b) => (b.style.opacity = "1"));
    } else {
      bubbles.forEach((b) => {
        b.style.opacity = "0";
        b.style.transform = "translateY(8px)";
        b.style.transition = "opacity .35s ease, transform .35s ease";
      });

      const io = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            bubbles.forEach((b, i) => {
              setTimeout(() => {
                b.style.opacity = "1";
                b.style.transform = "translateY(0)";
              }, i * 520);
            });
            io.disconnect();
          });
        },
        { threshold: 0.4 }
      );
      io.observe(chatBody);
    }
  }

  // ---------------------------------------------------------------- demo form
  const form = $("#demoForm");
  const msg = $("#formMsg");
  const btn = $("#demoBtn");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!msg) return;

      const data = Object.fromEntries(new FormData(form).entries());
      const phone = String(data.phone || "").trim();

      // Cheap client-side sanity check so we don't send garbage to the API.
      const digits = phone.replace(/\D/g, "");
      if (digits.length < 8) {
        msg.className = "form-msg err";
        msg.textContent = "That phone number looks too short — include the country code.";
        return;
      }

      btn.disabled = true;
      btn.textContent = "Sending…";
      msg.className = "form-msg";
      msg.textContent = "";

      const payload = {
        ...data,
        source: "landing-demo-form",
        submittedAt: new Date().toISOString(),
        page: location.href,
        referrer: document.referrer || null,
      };

      try {
        const res = await fetch(CONFIG.demoEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error("HTTP " + res.status);

        msg.className = "form-msg ok";
        msg.textContent =
          "Done — check your phone in the next few minutes for the demo text. (Nothing else will be sent.)";
        form.reset();
      } catch (err) {
        // Never lose a lead because the API is down: fall back to a prefilled email.
        const subject = encodeURIComponent("CallLoop demo request — " + (data.biz || "New lead"));
        const body = encodeURIComponent(
          Object.entries(payload)
            .map(([k, v]) => `${k}: ${v}`)
            .join("\n")
        );
        msg.className = "form-msg ok";
        msg.innerHTML =
          'Almost — send this from your email and we\'ll reply within the hour: ' +
          '<a href="' + CONFIG.mailFallback + "?subject=" + subject + "&body=" + body + '">open the prefilled email</a>.';
      } finally {
        btn.disabled = false;
        btn.textContent = "Send me the demo";
      }
    });
  }

  // ---------------------------------------------------------------- nav active state
  const navLinks = $$(".links a");
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
