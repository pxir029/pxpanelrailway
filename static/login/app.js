/* PXPanel 14 — Login only */
(function () {
  const modal = document.getElementById("welcomeModal");
  const closeBtn = document.getElementById("modalClose");
  const okBtn = document.getElementById("modalOk");
  const errEl = document.getElementById("err");

  function openModal() {
    if (!modal) return;
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
  }
  function closeModal() {
    if (!modal) return;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    try { sessionStorage.setItem("px_welcome_seen", "1"); } catch (e) {}
  }

  closeBtn && closeBtn.addEventListener("click", closeModal);
  okBtn && okBtn.addEventListener("click", closeModal);
  modal && modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

  async function boot() {
    try {
      const r = await fetch("/api/setup/status", { cache: "no-store" });
      const data = await r.json();
      if (data.needs_setup) {
        window.location.replace("/setup");
        return;
      }
    } catch (e) {}
    let seen = false;
    try { seen = sessionStorage.getItem("px_welcome_seen") === "1"; } catch (e) {}
    if (!seen) setTimeout(openModal, 350);
  }

  async function doLogin(e) {
    e.preventDefault();
    errEl.textContent = "";
    const btn = document.getElementById("btn");
    btn.disabled = true;
    const username = (document.getElementById("user")?.value || "").trim();
    const password = document.getElementById("pass").value;
    try {
      const r = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username, password }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        errEl.textContent = typeof data.detail === "string" ? data.detail : "ورود ناموفق";
        btn.disabled = false;
        return;
      }
      window.location.href = "/dashboard";
    } catch (ex) {
      errEl.textContent = "خطای شبکه — دوباره تلاش کنید";
      btn.disabled = false;
    }
  }

  document.getElementById("form")?.addEventListener("submit", doLogin);
  document.addEventListener("DOMContentLoaded", boot);
})();
