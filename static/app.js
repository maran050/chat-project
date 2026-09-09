
const API_BASE = ""; // عدِّل إذا كان الـ API في دومين/باث مختلف

/* ---------------------------
   Global state & DOM refs
   --------------------------- */
let token = localStorage.getItem("token");
let username = localStorage.getItem("username");
let user_id = localStorage.getItem("user_id");

let ws = null;
/* بعض عناصر DOM قد لا تكون موجودة في كل صفحة -> نتحقق عند الاستخدام */
const body = document.body;

/* vars for LocalStorage manager (initialized on DOMContentLoaded) */
let keyInput, valueInput, btnAdd, tableBody;

/* ---------------------------
   DOMContentLoaded: تهيئة عامة
   --------------------------- */
window.addEventListener("DOMContentLoaded", () => {
  // --- AUTH (login/register) handlers ---
  const btnLogin = document.getElementById("btnLogin");
  const btnRegister = document.getElementById("btnRegister");
  const showRegister = document.getElementById("showRegister");
  const showLogin = document.getElementById("showLogin");

  if (btnLogin) {
    btnLogin.addEventListener("click", login);
  }
  if (btnRegister) {
    btnRegister.addEventListener("click", register);
  }
  if (showRegister) {
    showRegister.addEventListener("click", () => {
      const loginForm = document.getElementById("loginForm");
      const registerForm = document.getElementById("registerForm");
      loginForm && loginForm.classList.add("hidden");
      registerForm && registerForm.classList.remove("hidden");
    });
  }
  if (showLogin) {
    showLogin.addEventListener("click", () => {
      const loginForm = document.getElementById("loginForm");
      const registerForm = document.getElementById("registerForm");
      registerForm && registerForm.classList.add("hidden");
      loginForm && loginForm.classList.remove("hidden");
    });
  }

  // --- Chat setup (if chat page) ---
  const btnSend = document.getElementById("btnSend");
  if (btnSend) {
    if (!token) { // if not logged in -> redirect to login
      window.location.href = "./login.html";
      return;
    }
    setupChat();
  }

  // --- Theme & color picker init ---
  const changTheme = document.getElementById("them");
  const colorPicker = document.getElementById("primaryColorPicker");
  const savedTheme = localStorage.getItem("theme") || "light";
  const savedColor = localStorage.getItem("primaryColor") || "#f8f8f8ff";
  document.documentElement.style.setProperty("--primary-color", savedColor);
  theme(savedTheme);

  if (changTheme) changTheme.addEventListener("click", toggleTheme);
  if (colorPicker) {
    colorPicker.value = savedColor;
    colorPicker.addEventListener("input", changePrimaryColor);
  }

  // --- username display if present ---
  const usernameEl = document.getElementById("username");
  if (usernameEl) usernameEl.innerText = username || "";

  // --- Admin panel initial load ---
  updateUserCount();
  if (document.getElementById("usersTableBody")) {
    loadUsers();
  }
  if (document.getElementById("messagesTableBody")) {
    loadMessages();
  }

  // --- LocalStorage page init ---
  keyInput = document.getElementById("keyInput");
  valueInput = document.getElementById("valueInput");
  btnAdd = document.getElementById("btnAdd");
  tableBody = document.querySelector("#storageTable tbody");

  if (tableBody) {
    loadTable();
    setupLocalStorageEvents();
  }

  // --- Slider init (if any) ---
  initSlider();
});

/* ======================================
   Auth: login / register
   ====================================== */
async function login() {
  try {
    const u = document.getElementById("loginUsername").value;
    const p = document.getElementById("loginPassword").value;

    const res = await fetch(API_BASE + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: u, password: p })
    });

    if (!res.ok) {
      const authMsg = document.getElementById("authMsg");
      if (authMsg) authMsg.innerText = "خطأ في تسجيل الدخول";
      return;
    }

    const data = await res.json();
    // backend returns access_token
    localStorage.setItem("token", data.access_token || data.accessToken || "");
    localStorage.setItem("username", data.username || u);
    localStorage.setItem("user_id", data.user_id || data.userId || "");

    // redirect to index (chat/dashboard)
    window.location.href = "./index.html";
  } catch (err) {
    console.error("login error:", err);
    const authMsg = document.getElementById("authMsg");
    if (authMsg) authMsg.innerText = "خطأ في تسجيل الدخول";
  }
}

async function register() {
  try {
    const u = document.getElementById("regUsername").value;
    const e = document.getElementById("regEmail").value;
    const p = document.getElementById("regPassword").value;

    const res = await fetch(API_BASE + "/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: u, email: e, password: p })
    });

    const data = await res.json();
    if (res.ok) {
      alert("تم إنشاء الحساب بنجاح. يمكنك تسجيل الدخول الآن.");
      window.location.href = "./login.html";
    } else {
      const regMsg = document.getElementById("regMsg");
      if (regMsg) regMsg.innerText = data.detail || "خطأ";
    }
  } catch (err) {
    console.error("register error:", err);
    const regMsg = document.getElementById("regMsg");
    if (regMsg) regMsg.innerText = "خطأ في التسجيل";
  }
}

/* ======================================
   Navigation helpers
   ====================================== */
function logout() {
  localStorage.removeItem("token");
  window.location.href = "./../login.html";
}

function dashBord() {
  window.location.href = "./dashbord/dashbord.html";
}

function openChat() {
  window.location.href = "./../index.html";
}

function backDashbord() {
  window.location.href = "./dashbord.html";
}

/* دالة ذاتية التنفيذ */
(function initChatNumberFromLS() {
  const msgNumber = localStorage.getItem("msgnumber");
  const chatNumEl = document.getElementById("chatnumber");
  if (chatNumEl && msgNumber !== null) chatNumEl.innerText = msgNumber;
})();

/* ======================================
   Theme & primary color logic
   ====================================== */
function theme(them) {
  const themeIcon = document.getElementById("them-icon");
  if (them === "dark") {
    body.classList.remove("light");
    body.classList.add("dark");
    if (themeIcon) {
      themeIcon.classList.remove("bi-sun");
      themeIcon.classList.add("bi-moon");
    }
    swapPanelClasses("dark");
  } else {
    body.classList.remove("dark");
    body.classList.add("light");
    if (themeIcon) {
      themeIcon.classList.remove("bi-moon");
      themeIcon.classList.add("bi-sun");
    }
    swapPanelClasses("light");
  }
}

function toggleTheme() {
  const newTheme = body.classList.contains("light") ? "dark" : "light";
  theme(newTheme);
  localStorage.setItem("theme", newTheme);
}

function swapPanelClasses(mode) {
  const panels = ["users-box", "chat-box", "title-info", "menu"];
  panels.forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    // remove opposite then add desired
    if (mode === "dark") {
      el.classList.remove("panal-light");
      el.classList.add("panal-dark");
    } else {
      el.classList.remove("panal-dark");
      el.classList.add("panal-light");
    }
  });
}

function changePrimaryColor(ev) {
  const color = ev.target.value;
  document.documentElement.style.setProperty("--primary-color", color);
  localStorage.setItem("primaryColor", color);
}

/* ======================================
   Chat logic (messages + WebSocket)
   ====================================== */
async function setupChat() {
  username = localStorage.getItem("username");
  token = localStorage.getItem("token");

  const btnSend = document.getElementById("btnSend");
  if (btnSend) btnSend.onclick = sendMsg;

  // Load last messages (public)
  try {
    const res = await fetch(API_BASE + "/messages");
    if (res.ok) {
      const msgs = await res.json();
      msgs.forEach(renderMessage);
    } else {
      console.warn("Could not load messages:", res.status);
    }
  } catch (err) {
    console.error("Error loading messages:", err);
  }

  // Open WebSocket (if token present)
  try {
    if (!token) return;
    ws = new WebSocket(`ws://${window.location.host}/ws?token=${token}`);

    ws.onopen = () => {
      const connState = document.getElementById("connState");
      if (connState) connState.innerText = "متصل";
    };

    ws.onclose = () => {
      const connState = document.getElementById("connState");
      if (connState) connState.innerText = "مغلق";
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "system") renderSystem(msg.message);
        else if (msg.type === "message") renderMessage(msg);
      } catch (err) {
        console.error("ws onmessage parse error:", err);
      }
    };
  } catch (err) {
    console.error("WebSocket error:", err);
  }

  // load message count (best-effort)
  loadMessageCount();
}

function sendMsg() {
  const input = document.getElementById("msgInput");
  if (!input) return;
  const content = input.value.trim();
  if (!content) return;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.warn("WebSocket not open");
    input.value = "";
    return;
  }
  ws.send(JSON.stringify({ content: content}));
  input.value = "";
}

function renderMessage(msg) {
  const msgsContainer = document.getElementById("msgs");
  if (!msgsContainer) return;
  const div = document.createElement("div");
  div.classList.add("msg");
  div.classList.add(msg.sender_username === username ? "you" : "other");
  div.innerText = `${msg.sender_username}\t${msg.timestamp} \n ${msg.content}`;
  msgsContainer.appendChild(div);
  // scroll to bottom
  msgsContainer.scrollTop = msgsContainer.scrollHeight;
}

function renderSystem(text) {
  const msgsContainer = document.getElementById("msgs");
  if (!msgsContainer) return;
  const div = document.createElement("div");
  div.classList.add("system");
  div.innerText = text;
  msgsContainer.appendChild(div);
  msgsContainer.scrollTop = msgsContainer.scrollHeight;
}

async function loadMessageCount() {
  try {
    token = localStorage.getItem("token");
    const res = await fetch(`${API_BASE}/messages/count?token=${token}`);
    if (!res.ok) {
      console.warn("messages/count failed", res.status);
      return;
    }
    const data = await res.json();
    localStorage.setItem("msgnumber", `${data.count}`);
    const chatNumEl = document.getElementById("chatnumber");
    if (chatNumEl) chatNumEl.innerText = `${data.count}`;
  } catch (err) {
    console.error("loadMessageCount error:", err);
  }
}

/* ======================================
   Admin panel: users & messages management
   ====================================== */
async function updateUserCount() {
  try {
    const res = await fetch(API_BASE + "/users/count");
    if (!res.ok) {
      console.warn("/users/count failed", res.status);
      return;
    }
    const data = await res.json();
    localStorage.setItem("usercounter", `${data.count}`);
    const userNumEl = document.getElementById("usernum");
    if (userNumEl) userNumEl.innerText = `${data.count}`;
  } catch (err) {
    console.error("updateUserCount error:", err);
  }
}

async function loadUsers() {
  try {
    const res = await fetch(API_BASE + "/users");
    if (!res.ok) {
      console.error("loadUsers: response not ok", await res.json());
      return;
    }
    const users = await res.json();
    if (!Array.isArray(users)) {
      console.error("loadUsers: expected array, got:", users);
      return;
    }
    const tbody = document.getElementById("usersTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    users.forEach((u) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${u.username}</td>
        <td>${u.email || ""}</td>
        <td>
          <button onclick="deleteUser(${u.id})">حذف</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("loadUsers error:", err);
  }
}

async function deleteUser(id) {
  if (!confirm("هل تريد حذف هذا المستخدم؟")) return;
  try {
    await fetch(API_BASE + `/admin/user/${id}`, { method: "DELETE" });
    loadUsers();
    updateUserCount();
  } catch (err) {
    console.error("deleteUser error:", err);
  }
}

async function loadMessages() {
  try {
    const res = await fetch(API_BASE + "/messages");
    if (!res.ok) {
      console.warn("loadMessages failed", res.status);
      return;
    }
    const msgs = await res.json();
    const tbody = document.getElementById("messagesTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    msgs.forEach((m) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${m.sender_username}</td>
        <td contenteditable="true" onblur="updateMessage(${m.id}, this)">${m.content}</td>
        <td><button onclick="updateMessage(${m.id}, this.previousElementSibling)">حفظ</button></td>
        <td><button onclick="deleteMessage(${m.id})">حذف</button></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("loadMessages error:", err);
  }
}

async function updateMessage(id, el) {
  try {
    // el can be a TD element or the button's previous sibling (td)
    const content = (el && el.innerText) ? el.innerText : "";
    await fetch(API_BASE + `/admin/message/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: content })
    });
    alert("تم تعديل الرسالة");
  } catch (err) {
    console.error("updateMessage error:", err);
  }
}

async function deleteMessage(id) {
  if (!confirm("هل تريد حذف هذه الرسالة؟")) return;
  try {
    await fetch(API_BASE + `/admin/message/${id}`, { method: "DELETE" });
    loadMessages();
    loadMessageCount();
  } catch (err) {
    console.error("deleteMessage error:", err);
  }
}

/* ======================================
   Image slider (safeguarded)
   ====================================== */
let sliderIntervalId = null;
function initSlider() {
  const slides = document.querySelector(".slides");
  if (!slides) return;
  const images = slides.querySelectorAll("img");
  const prev = document.querySelector(".prev");
  const next = document.querySelector(".next");
  if (!images || images.length === 0) return;

  let index = 0;

  function showSlide(i) {
    index = (i + images.length) % images.length;
    const slideWidth = images[0].clientWidth || slides.clientWidth;
    slides.style.transform = `translateX(${-index * slideWidth}px)`;
  }

  if (next) next.addEventListener("click", () => showSlide(index + 1));
  if (prev) prev.addEventListener("click", () => showSlide(index - 1));

  // clear previous if any, then set interval
  if (sliderIntervalId) clearInterval(sliderIntervalId);
  sliderIntervalId = setInterval(() => showSlide(index + 1), 3000);

  // initial show
  
  slides.addEventListener("mouseenter", () => {
  if (sliderIntervalId) clearInterval(sliderIntervalId);
});

slides.addEventListener("mouseleave", () => {
  sliderIntervalId = setInterval(() => showSlide(index + 1), 3000);
});
showSlide(0);
}


/* ======================================
   LocalStorage Manager
   ====================================== */
function loadTable() {
  if (!tableBody) return;
  tableBody.innerHTML = "";

  if (localStorage.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="3" class="text-center">لا توجد عناصر مخزنة</td>`;
    tableBody.appendChild(tr);
    return;
  }

  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const value = localStorage.getItem(key);

    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(key)}</td>
      <td contenteditable="true" data-key="${escapeHtml(key)}">${escapeHtml(value)}</td>
      <td>
        <button class="action-btn edit" data-key="${escapeHtml(key)}">💾 حفظ</button>
        <button class="action-btn delete" data-key="${escapeHtml(key)}">🗑 حذف</button>
      </td>
    `;
    tableBody.appendChild(row);
  }
}

function setupLocalStorageEvents() {
  if (btnAdd) {
    btnAdd.addEventListener("click", () => {
      const key = keyInput ? keyInput.value.trim() : "";
      const value = valueInput ? valueInput.value.trim() : "";
      if (!key || !value) {
        alert("الرجاء إدخال مفتاح وقيمة");
        return;
      }
      localStorage.setItem(key, value);
      if (keyInput) keyInput.value = "";
      if (valueInput) valueInput.value = "";
      loadTable();
    });
  }

  if (!tableBody) return;
  tableBody.addEventListener("click", (e) => {
    const target = e.target;
    const key = target.dataset ? target.dataset.key : null;
    if (!key) return;

    if (target.classList.contains("delete")) {
      if (confirm(`هل تريد حذف العنصر "${key}"؟`)) {
        localStorage.removeItem(key);
        loadTable();
      }
    } else if (target.classList.contains("edit")) {
      const td = tableBody.querySelector(`td[contenteditable][data-key="${cssEscape(key)}"]`);
      if (!td) return;
      const newValue = td.innerText.trim();
      localStorage.setItem(key, newValue);
      alert(`تم تحديث "${key}"`);
      loadTable();
    }
  });
}

/* ======================================
   Utilities
   ====================================== */
function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return "";
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* simple css escape for attribute selectors (not perfect but practical) */
function cssEscape(s) {
  return s.replace(/(["'\\])/g, "\\$1");
}
