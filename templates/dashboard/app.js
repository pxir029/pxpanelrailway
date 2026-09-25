/* PXPanel 15 — Dashboard app (Railway-safe) */
window.APP_VERSION = "15.0.0";

function setTxt(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function setHtml(id, val) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = val;
}

const I18N = {
  fa: {
    logout: "خروج",
    loading: "در حال بارگذاری...",
    refresh: "بروزرسانی",
  },
  en: { logout: "Logout", loading: "Loading...", refresh: "Refresh" },
};
let lang = localStorage.getItem("px_lang") || "fa";
let statRange = "month";
let __allLinks = [];
let __linksMap = {};
window.__linksMap = __linksMap;

function t(k) {
  return (I18N[lang] || I18N.fa)[k] || k;
}
function applyLang() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    if (I18N[lang] && I18N[lang][k]) el.textContent = I18N[lang][k];
  });
}
function setLang(l) {
  lang = l;
  localStorage.setItem("px_lang", l);
  applyLang();
}

function setTheme(mode) {
  const m = mode === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", m);
  document.documentElement.classList.toggle("light", m === "light");
  document.body && document.body.setAttribute("data-theme", m);
  localStorage.setItem("px_theme", m);
  const lab = document.getElementById("themeLabel");
  if (lab) lab.textContent = m === "light" ? "تم تیره" : "تم روشن";
}
function toggleTheme() {
  const cur = localStorage.getItem("px_theme") || "dark";
  setTheme(cur === "light" ? "dark" : "light");
}

/* Sidebar / mobile */
const sb = document.getElementById("sidebar");
const main = document.getElementById("main");
(function initNav() {
  const sbT = document.getElementById("sbToggle");
  if (sbT)
    sbT.onclick = () => {
      sb && sb.classList.toggle("collapsed");
      main && main.classList.toggle("expanded");
    };
  const mob = document.getElementById("mobMenuBtn");
  const ov = document.getElementById("overlay");
  if (mob)
    mob.onclick = () => {
      sb && sb.classList.add("open");
      if (ov) {
        ov.classList.add("show");
        ov.classList.add("on");
      }
    };
  if (ov)
    ov.onclick = () => {
      sb && sb.classList.remove("open");
      ov.classList.remove("show");
      ov.classList.remove("on");
    };
})();

function goPage(name) {
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("on", n.dataset.page === name));
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("on", p.id === "page-" + name));
  if (sb) sb.classList.remove("open");
  const ov = document.getElementById("overlay");
  if (ov) {
    ov.classList.remove("show");
    ov.classList.remove("on");
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (name === "logs") loadLogs();
  if (name === "configs" || name === "dash" || name === "stats") refreshAll();
  if (name === "telegram") {
    if (typeof loadTelegram === "function") loadTelegram();
    if (typeof loadUserBots === "function") loadUserBots();
  }
  if (name === "groups") loadGroups();
  if (name === "news") loadNews();
  if (name === "admins") loadAdmins();
  if (name === "settings") loadSecurity();
}
document.querySelectorAll(".nav-item").forEach((el) => {
  el.addEventListener("click", () => goPage(el.dataset.page));
});

function toast(msg) {
  let el = document.getElementById("toast");
  if (!el) {
    const w = document.getElementById("toastWrap");
    if (w) {
      el = document.createElement("div");
      el.className = "toast";
      el.id = "toast";
      w.appendChild(el);
    }
  }
  if (!el) {
    console.log("[toast]", msg);
    return;
  }
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove("show"), 2600);
}

async function doLogout() {
  try {
    await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
  } catch (e) {}
  try {
    localStorage.clear();
    sessionStorage.clear();
  } catch (e) {}
  location.href = "/login";
}

async function api(url, opts = {}) {
  try {
    const r = await fetch(url, { cache: "no-store", credentials: "same-origin", ...opts });
    if (r.status === 401) {
      location.href = "/login";
      return null;
    }
    let data = null;
    try {
      data = await r.json();
    } catch {
      data = {};
    }
    if (!r.ok) {
      toast(data.detail || data.error || "Error");
      return null;
    }
    return data;
  } catch (e) {
    toast(lang === "fa" ? "ارتباط برقرار نشد" : "Connection failed");
    return null;
  }
}

function fmtB(b) {
  b = Number(b) || 0;
  if (b < 1024) return b + " B";
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + " KB";
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(2) + " MB";
  return (b / 1024 ** 3).toFixed(2) + " GB";
}
function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function randomName() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < 10; i++) s += chars[Math.floor(Math.random() * chars.length)];
  if (/^[0-9]/.test(s)) s = "a" + s.slice(1);
  const el = document.getElementById("cName");
  if (el) el.value = s;
  return s;
}

async function refreshAll() {
  try {
    const sys = await api("/api/system");
    if (sys) {
      setTxt("sysCpu", sys.cpu_percent != null ? sys.cpu_percent.toFixed(1) + "%" : "—");
      setTxt("sysRam", sys.ram_used_fmt || "—");
      setTxt("sysRamPct", sys.ram_percent != null ? sys.ram_percent.toFixed(1) + "%" : "—");
      setTxt("sysNetUp", sys.net_sent_fmt || "—");
      setTxt("sysNetDown", sys.net_recv_fmt || "—");
      setTxt("sysDisk", sys.disk_used_fmt || "—");
      setTxt("sysDiskPct", sys.disk_percent != null ? sys.disk_percent.toFixed(1) + "%" : "—");
      if (sys.uptime) {
        setTxt("mUptime", sys.uptime);
        setTxt("sUptime", sys.uptime);
      }
    }
  } catch (e) {}

  const links = await api("/api/links");
  if (!links) return;
  const arr = Array.isArray(links.links) ? links.links : Array.isArray(links) ? links : [];
  __allLinks = arr;
  __linksMap = {};
  arr.forEach((l) => {
    if (l && l.uuid) __linksMap[l.uuid] = l;
  });
  window.__linksMap = __linksMap;

  let active = 0,
    used = 0;
  arr.forEach((l) => {
    if (l.active !== false) active++;
    used += Number(l.used_bytes || 0);
  });
  setTxt("mLinks", arr.length);
  setTxt("mLinks2", arr.length);
  setTxt("sLinks", arr.length);
  setTxt("mTraffic", fmtB(used));
  setTxt("sTraffic", fmtB(used));
  setTxt("sActive", active);
  setTxt("lastUpd", (lang === "fa" ? "بروزرسانی: " : "Updated: ") + new Date().toLocaleTimeString(lang === "fa" ? "fa-IR" : "en-US"));

  try {
    const c = await api("/api/connections");
    const cnt = c && c.connections ? c.connections.length : c && typeof c.count === "number" ? c.count : 0;
    setTxt("mConns", cnt);
    setTxt("sConns", cnt);
  } catch (e) {}

  try {
    const h = await fetch("/health", { cache: "no-store" }).then((r) => r.json());
    if (h && h.uptime) {
      setTxt("mUptime", h.uptime);
      setTxt("sUptime", h.uptime);
    }
  } catch (e) {}

  setHtml(
    "panelInfo",
    lang === "fa"
      ? `کل کانفیگ: <b>${arr.length}</b> · فعال: <b>${active}</b> · مصرف: <b>${fmtB(used)}</b>`
      : `Total: <b>${arr.length}</b> · Active: <b>${active}</b> · Usage: <b>${fmtB(used)}</b>`
  );

  renderLinks(arr);
  renderDashConfigs(arr);
  try { loadStatsChart(); } catch (e) {}
}

function renderLinks(arr) {
  const tb = document.getElementById("linksTable") || document.getElementById("linksBody");
  if (!tb) return;
  if (!arr.length) {
    tb.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--muted)">کانفیگی نیست</td></tr>`;
    return;
  }
  tb.innerHTML = arr
    .map((l) => {
      const uid = esc(l.uuid || l.id || "");
      const name = esc(l.label || l.name || uid.slice(0, 8));
      const proto = esc(l.protocol_label || l.protocol || "—");
      const on = l.active !== false;
      const used = fmtB(l.used_bytes || 0);
      const lim = Number(l.limit_bytes || 0) ? fmtB(l.limit_bytes) : "∞";
      return `<tr data-uid="${uid}">
      <td>${name}</td>
      <td>${proto}</td>
      <td><span class="badge ${on ? "on" : "off"}">${on ? "فعال" : "خاموش"}</span></td>
      <td>${used} / ${lim}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm" type="button" onclick="copyLinkById('${uid}')">کپی</button>
        <button class="btn btn-sm" type="button" onclick="toggleLink('${uid}',${!on})">${on ? "خاموش" : "روشن"}</button>
        <button class="btn btn-sm btn-danger" type="button" onclick="deleteLink('${uid}')">حذف</button>
      </td>
    </tr>`;
    })
    .join("");
}

function renderDashConfigs(arr) {
  const box = document.getElementById("dashConfigs");
  if (!box) return;
  if (!arr.length) {
    box.innerHTML = `<div style="color:var(--muted);font-size:13px;padding:12px;text-align:center">هنوز کانفیگی ساخته نشده</div>`;
    return;
  }
  const top = arr.slice(0, 12);
  box.innerHTML = top
    .map((l) => {
      const uid = esc(l.uuid || l.id || "");
      const name = esc(l.label || l.name || uid.slice(0, 8));
      const proto = esc(l.protocol_label || l.protocol || "");
      const on = l.active !== false;
      return `<div class="dash-cfg-row">
      <div class="dash-cfg-info">
        <strong>${name}</strong>
        <span>${proto}</span>
        <span class="badge ${on ? "on" : "off"}">${on ? "فعال" : "خاموش"}</span>
      </div>
      <div class="dash-cfg-ops">
        <button class="btn btn-sm" type="button" onclick="copyLinkById('${uid}')">کپی</button>
        <button class="btn btn-sm btn-danger" type="button" onclick="deleteLink('${uid}')">حذف</button>
      </div>
    </div>`;
    })
    .join("");
}

function getLinkUrl(l) {
  if (!l) return "";
  return l.vless_full || l.vless || l.vless_link || l.link || "";
}
function getSubUrl(l) {
  if (!l) return "";
  return l.sub || l.sub_url || l.info || "";
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text || "");
    toast(lang === "fa" ? "کپی شد" : "Copied");
  } catch (e) {
    toast("Copy failed");
  }
}
async function copyLinkById(uid) {
  await copyText(getLinkUrl((__linksMap || {})[uid]));
}
async function copySubById(uid) {
  await copyText(getSubUrl((__linksMap || {})[uid]));
}

async function toggleLink(uid, state) {
  const r = await api("/api/links/" + uid, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ active: !!state }),
  });
  if (r !== null) {
    toast(lang === "fa" ? "به‌روز شد" : "Updated");
    refreshAll();
  }
}

async function deleteLink(uid) {
  if (!confirm(lang === "fa" ? "حذف این کانفیگ؟" : "Delete this config?")) return;
  const r = await api("/api/links/" + uid, { method: "DELETE" });
  if (r !== null) {
    toast(lang === "fa" ? "حذف شد" : "Deleted");
    refreshAll();
  }
}

function showResult(data) {
  const m = document.getElementById("resultModal");
  if (!m) return;
  setTxt("resVless", data.vless || data.vless_full || data.link || "");
  setTxt("resSub", data.sub || data.sub_url || "");
  m.classList.add("open");
}
function closeResult() {
  const m = document.getElementById("resultModal");
  if (m) m.classList.remove("open");
}

async function doCreate() {
  const label = (document.getElementById("cName")?.value || "").trim() || randomName();
  const protocol = document.getElementById("cProto")?.value || "vless-ws";
  const config_count = Number(document.getElementById("cCount")?.value || 1);
  const limit = Number(document.getElementById("cLimit")?.value || 0);
  const unit = document.getElementById("cUnit")?.value || "GB";
  const days = Number(document.getElementById("cDays")?.value || 0);
  const ip = Number(document.getElementById("cIp")?.value || 0);
  const speed = Number(document.getElementById("cSpeed")?.value || 0);
  let limit_bytes = 0;
  if (limit > 0 && unit !== "0") {
    limit_bytes = unit === "MB" ? limit * 1024 * 1024 : limit * 1024 * 1024 * 1024;
  }
  const body = {
    label,
    protocol,
    config_count,
    limit_bytes,
    days,
    connection_limit: ip,
    speed_limit_mbps: speed,
  };
  const r = await api("/api/links", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (r) {
    toast(lang === "fa" ? "ساخته شد" : "Created");
    showResult(r);
    refreshAll();
  }
}

async function doAutoCreate() {
  const r = await api("/api/links/auto", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ config_count: 1, protocol: "vless-ws" }),
  });
  if (r) {
    toast(lang === "fa" ? "ساخته شد" : "Created");
    showResult(r);
    refreshAll();
  }
}

async function loadProtocols() {
  const sel = document.getElementById("cProto");
  if (!sel) return;
  const r = await api("/api/protocols");
  const list = (r && r.protocols) || [];
  if (!list.length) return;
  const def = (r && r.default) || "vless-ws";
  sel.innerHTML = list.map((p) => `<option value="${esc(p.id)}" ${p.id === def ? "selected" : ""}>${esc(p.label || p.id)}</option>`).join("");
}

async function loadGroups() {
  const box = document.getElementById("groupsBox");
  if (!box) return;
  const r = await api("/api/subs");
  const arr = (r && r.subs) || (Array.isArray(r) ? r : []);
  if (!arr.length) {
    box.innerHTML = '<div style="color:var(--muted)">گروهی نیست</div>';
    return;
  }
  box.innerHTML = arr
    .map((s) => `<div style="padding:10px;border:1px solid var(--border);border-radius:10px;margin-bottom:8px"><b>${esc(s.name || s.label || s.id)}</b></div>`)
    .join("");
}

async function loadLogs() {
  const box = document.getElementById("logsBox");
  if (!box) return;
  const r = await api("/api/activity");
  const logs = (r && r.logs) || [];
  box.textContent = logs.length ? logs.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join("\n") : "—";
}

async function loadNews() {
  const box = document.getElementById("newsBox");
  if (!box) return;
  const r = await api("/api/news");
  box.innerHTML = r ? `<pre style="white-space:pre-wrap;font-size:12px">${esc(JSON.stringify(r, null, 2))}</pre>` : "—";
}

async function loadAdmins() {
  const box = document.getElementById("adminsBox");
  if (!box) return;
  const r = await api("/api/admins");
  const list = (r && r.admins) || [];
  box.innerHTML = list.length
    ? list.map((a) => `<div style="padding:8px 0;border-bottom:1px solid var(--border)">${esc(a.username || a.id)}</div>`).join("")
    : "—";
}

async function loadMe() {
  const r = await api("/api/me");
  if (!r) return;
  const role = r.role || "owner";
  const perms = r.permissions || {};
  document.querySelectorAll(".nav-item[data-perm]").forEach((el) => {
    const p = el.getAttribute("data-perm");
    if (role === "owner") {
      el.style.display = "";
      return;
    }
    el.style.display = perms[p] ? "" : "none";
  });
}

async function loadTelegram() {
  const r = await api("/api/telegram/settings");
  if (!r) return;
  if (r.admin_ids) {
    const el = document.getElementById("tgAdmin");
    if (el) el.value = r.admin_ids;
  }
  const wh = document.getElementById("tgWebhook");
  if (wh) wh.checked = r.webhook !== false;
  const st = document.getElementById("tgStatus");
  if (st) st.textContent = r.has_token ? "توکن ذخیره شده: " + (r.token_masked || "") : "";
}

async function saveTelegram() {
  const token = (document.getElementById("tgToken")?.value || "").trim();
  const admin = (document.getElementById("tgAdmin")?.value || "").trim();
  const webhook = document.getElementById("tgWebhook")?.checked;
  if (!token || !admin) {
    toast("توکن و آیدی لازم است");
    return;
  }
  const r = await api("/api/telegram/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, admin_ids: admin, webhook }),
  });
  if (r) {
    setTxt("tgStatus", r.message || "فعال شد");
    toast(r.message || "OK");
  }
}

async function changePassword() {
  const current_password = document.getElementById("pwCur")?.value || "";
  const new_password = document.getElementById("pwNew")?.value || "";
  const confirm = document.getElementById("pwCf")?.value || "";
  if (new_password !== confirm) {
    toast("تکرار رمز یکسان نیست");
    return;
  }
  const r = await api("/api/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password, new_password }),
  });
  if (r) toast("رمز تغییر کرد");
}

async function loadSecurity() {}

async function panelUpdate() {
  const m = document.getElementById("panelModal");
  const t = document.getElementById("panelModalTitle");
  const b = document.getElementById("panelModalBody");
  if (!m) {
    alert("v" + window.APP_VERSION);
    return;
  }
  if (t) t.textContent = "آپدیت پنل";
  if (b) b.innerHTML = `<p>نسخه فعلی: <b>v${window.APP_VERSION}</b></p>`;
  m.classList.add("open");
}

async function downloadBackup(kind) {
  try {
    const url = kind === "bot" ? "/api/backup/bot" : "/api/backup/users";
    const r = await fetch(url, { credentials: "same-origin", cache: "no-store" });
    if (r.status === 401) {
      location.href = "/login";
      return;
    }
    if (!r.ok) {
      toast("خطا");
      return;
    }
    const text = await r.text();
    const blob = new Blob([text], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "pxpanel-" + kind + ".json";
    a.click();
    toast("دانلود شد");
  } catch (e) {
    toast(String(e.message || e));
  }
}
async function restoreUsers() {
  toast("فایل را انتخاب کنید");
}
async function restoreBot() {
  toast("فایل را انتخاب کنید");
}

async function createAdmin() {
  toast("در حال ساخت...");
}

/* User bots */
async function addUserBot() {
  const label = (document.getElementById("ubLabel")?.value || "").trim();
  const token = (document.getElementById("ubToken")?.value || "").trim();
  const admin = (document.getElementById("ubAdmin")?.value || "").trim();
  const protocol = document.getElementById("ubProto")?.value || "vless-ws";
  const st = document.getElementById("ubStatus");
  if (!token || !admin) {
    if (st) st.textContent = "توکن و آیدی لازم است";
    return;
  }
  const r = await api("/api/telegram/user-bots", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label, token, admin_ids: admin, protocol }),
  });
  if (r) {
    if (st) st.textContent = r.message || "ثبت شد";
    loadUserBots();
  }
}
async function loadUserBots() {
  const tb = document.getElementById("userBotsBody");
  if (!tb) return;
  const r = await api("/api/telegram/user-bots");
  const list = (r && r.bots) || [];
  if (!list.length) {
    tb.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted)">هنوز رباتی ثبت نشده</td></tr>';
    return;
  }
  tb.innerHTML = list
    .map(
      (b) => `<tr>
    <td>${esc(b.label || "—")}</td>
    <td>${esc(b.token_masked || "***")}</td>
    <td>${esc(b.admin_ids || "")}</td>
    <td><span class="badge ${b.active ? "on" : "off"}">${b.active ? "فعال" : "خاموش"}</span></td>
    <td><button class="btn btn-sm btn-danger" type="button" onclick="deleteUserBot('${esc(b.id)}')">حذف</button></td>
  </tr>`
    )
    .join("");
}
async function deleteUserBot(id) {
  if (!confirm("حذف؟")) return;
  await api("/api/telegram/user-bots/" + id, { method: "DELETE" });
  loadUserBots();
}


/* Real traffic chart */
let _chartData = [];
function drawTrafficChart(canvasId, hourly) {
  const c = document.getElementById(canvasId);
  if (!c || !c.getContext) return;
  const ctx = c.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth || 400;
  const h = c.clientHeight || 180;
  c.width = Math.floor(w * dpr);
  c.height = Math.floor(h * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  // build 24h series
  const keys = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600000);
    const k = String(d.getHours()).padStart(2, "0") + ":00";
    keys.push(k);
  }
  const data = keys.map((k) => Number((hourly && hourly[k]) || 0));
  _chartData = data;
  const max = Math.max(...data, 1);

  // grid
  ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue("--border").trim() || "#2e3748";
  ctx.lineWidth = 1;
  for (let i = 0; i < 4; i++) {
    const y = 12 + ((h - 28) * i) / 3;
    ctx.beginPath();
    ctx.moveTo(8, y);
    ctx.lineTo(w - 8, y);
    ctx.stroke();
  }

  const padL = 8, padR = 8, padT = 12, padB = 20;
  const cw = w - padL - padR;
  const ch = h - padT - padB;

  // area fill
  const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#3b82f6";
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = padL + (cw * i) / Math.max(data.length - 1, 1);
    const y = padT + ch - (ch * v) / max;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(padL + cw, padT + ch);
  ctx.lineTo(padL, padT + ch);
  ctx.closePath();
  ctx.fillStyle = accent + "22";
  try { ctx.fillStyle = "rgba(59,130,246,0.15)"; } catch (e) {}
  ctx.fill();

  // line
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = padL + (cw * i) / Math.max(data.length - 1, 1);
    const y = padT + ch - (ch * v) / max;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = accent || "#3b82f6";
  ctx.lineWidth = 2;
  ctx.lineJoin = "round";
  ctx.stroke();

  // dots on non-zero
  ctx.fillStyle = accent || "#3b82f6";
  data.forEach((v, i) => {
    if (!v) return;
    const x = padL + (cw * i) / Math.max(data.length - 1, 1);
    const y = padT + ch - (ch * v) / max;
    ctx.beginPath();
    ctx.arc(x, y, 2.5, 0, Math.PI * 2);
    ctx.fill();
  });

  // labels
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--muted").trim() || "#9aa8bd";
  ctx.font = "10px Inter, sans-serif";
  ctx.fillText(keys[0], padL, h - 6);
  ctx.fillText(keys[Math.floor(keys.length / 2)], w / 2 - 12, h - 6);
  ctx.fillText(keys[keys.length - 1], w - padR - 28, h - 6);
  ctx.fillText(fmtB(max), padL, 10);
}

async function loadStatsChart() {
  try {
    const r = await api("/stats");
    if (!r) return;
    setTxt("statReq", r.total_requests != null ? r.total_requests : "—");
    setTxt("statErr", r.total_errors != null ? r.total_errors : "—");
    setTxt("statActiveLinks", r.active_links != null ? r.active_links : "—");
    setTxt("statExpired", r.expired_links != null ? r.expired_links : "—");
    setTxt("statSubs", r.subs_count != null ? r.subs_count : "—");
    if (r.total_traffic_bytes != null) setTxt("mTraffic", fmtB(r.total_traffic_bytes));
    if (r.uptime) setTxt("mUptime", r.uptime);
    if (r.active_connections != null) setTxt("mConns", r.active_connections);
    drawTrafficChart("chartTraffic", r.hourly || {});
    drawTrafficChart("chartTrafficStats", r.hourly || {});
  } catch (e) {}
}

/* boot */
setTheme(localStorage.getItem("px_theme") || "dark");
applyLang();
loadMe();
loadProtocols();
refreshAll();
loadStatsChart();
setInterval(refreshAll, 5000);
setInterval(loadStatsChart, 15000);
window.addEventListener('resize', () => loadStatsChart());
