/* PXPanel 14 — First-run setup page */
(function () {
  const form = document.getElementById("setupForm");
  const errEl = document.getElementById("err");
  const btn = document.getElementById("setupBtn");

  function scorePassword(pw) {
    let s = 0;
    if (pw.length >= 6) s += 1;
    if (pw.length >= 10) s += 1;
    if (/[A-Za-z]/.test(pw) && /\d/.test(pw)) s += 1;
    if (/[^A-Za-z0-9]/.test(pw)) s += 1;
    return s;
  }

  function updateStrength() {
    const pw = document.getElementById("setupPass")?.value || "";
    const fill = document.getElementById("strengthFill");
    const text = document.getElementById("strengthText");
    if (!fill || !text) return;
    const s = scorePassword(pw);
    fill.style.width = [0, 25, 50, 75, 100][s] + "%";
    fill.className = s >= 3 ? "high" : s >= 2 ? "mid" : "";
    text.textContent =
      !pw ? "قدرت رمز را وارد کنید" :
      s <= 1 ? "ضعیف — رمز طولانی‌تر انتخاب کنید" :
      s === 2 ? "متوسط" :
      s === 3 ? "خوب" : "عالی";
  }

  document.getElementById("setupPass")?.addEventListener("input", updateStrength);

  async function ensureNeedsSetup() {
    try {
      const r = await fetch("/api/setup/status", { cache: "no-store" });
      const data = await r.json();
      if (!data.needs_setup) {
        window.location.replace("/login");
      }
    } catch (e) {}
  }

  async function doSetup(e) {
    e.preventDefault();
    errEl.textContent = "";
    const pw = document.getElementById("setupPass").value;
    const pw2 = document.getElementById("setupPass2").value;
    if (pw.length < 6) {
      errEl.textContent = "رمز باید حداقل ۶ کاراکتر باشد";
      return;
    }
    if (pw !== pw2) {
      errEl.textContent = "تکرار رمز یکسان نیست";
      return;
    }
    btn.disabled = true;
    try {
      const r = await fetch("/api/setup/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ password: pw, repeat_password: pw2 }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        errEl.textContent =
          typeof data.detail === "string" ? data.detail : "خطا در تنظیم رمز";
        btn.disabled = false;
        return;
      }
      window.location.href = "/dashboard";
    } catch (ex) {
      errEl.textContent = "خطای شبکه — دوباره تلاش کنید";
      btn.disabled = false;
    }
  }

  form?.addEventListener("submit", doSetup);
  document.addEventListener("DOMContentLoaded", ensureNeedsSetup);
})();
