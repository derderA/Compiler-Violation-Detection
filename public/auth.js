let adminToken = "";

function buildLoginModal() {
  const overlay = document.createElement("div");
  overlay.className = "modal-backdrop";
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <h2 id="modal-title">管理员登录</h2>
      <p class="muted">请输入管理员密码后继续操作。</p>
      <form id="modal-login-form" class="admin-form login-form">
        <label>
          <span>管理员密码</span>
          <input id="modal-password" type="password" autocomplete="current-password" required />
        </label>
        <div class="actions">
          <button type="submit">登录</button>
        </div>
      </form>
      <p id="modal-login-status" class="status-text hidden"></p>
    </div>
  `;
  document.body.appendChild(overlay);

  const form = overlay.querySelector("#modal-login-form");
  const passwordInput = overlay.querySelector("#modal-password");
  const status = overlay.querySelector("#modal-login-status");
  return { overlay, form, passwordInput, status };
}

function showChangePasswordStep({ overlay, token, currentPassword, resolve }) {
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-change-title">
      <h2 id="modal-change-title">设置新密码</h2>
      <p class="muted">首次登录需修改初始密码，请设置一个至少 6 位的新密码。</p>
      <form id="modal-change-form" class="admin-form login-form">
        <label>
          <span>新密码（至少 6 位）</span>
          <input id="modal-new-password" type="password" autocomplete="new-password" required />
        </label>
        <label>
          <span>确认新密码</span>
          <input id="modal-confirm-password" type="password" autocomplete="new-password" required />
        </label>
        <div class="actions">
          <button type="submit">确认修改并登录</button>
        </div>
      </form>
      <p id="modal-change-status" class="status-text hidden"></p>
    </div>
  `;

  const form = overlay.querySelector("#modal-change-form");
  const newPasswordInput = overlay.querySelector("#modal-new-password");
  const confirmPasswordInput = overlay.querySelector("#modal-confirm-password");
  const status = overlay.querySelector("#modal-change-status");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.classList.remove("hidden");
    status.textContent = "正在修改...";
    status.style.color = "#cbd5e1";

    if (newPasswordInput.value !== confirmPasswordInput.value) {
      status.textContent = "两次输入的密码不一致";
      status.style.color = "#fda4af";
      return;
    }

    try {
      const response = await fetch("/api/admin/change-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          currentPassword,
          newPassword: newPasswordInput.value,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error ?? "修改失败");
      }

      adminToken = token;
      overlay.remove();
      resolve(adminToken);
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : "修改失败";
      status.style.color = "#fda4af";
    }
  });
}

export async function requireAdmin() {
  if (adminToken) {
    return adminToken;
  }

  const { overlay, form, passwordInput, status } = buildLoginModal();
  passwordInput.focus();

  return new Promise((resolve) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      status.classList.remove("hidden");
      status.textContent = "正在登录...";
      status.style.color = "#cbd5e1";

      try {
        const loginPassword = passwordInput.value;
        const response = await fetch("/api/admin/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: loginPassword }),
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error ?? "登录失败");
        }

        if (data.mustChangePassword) {
          showChangePasswordStep({ overlay, token: data.token, currentPassword: loginPassword, resolve });
          return;
        }

        adminToken = data.token;
        passwordInput.value = "";
        overlay.remove();
        resolve(adminToken);
      } catch (error) {
        status.textContent = error instanceof Error ? error.message : "登录失败";
        status.style.color = "#fda4af";
      }
    });
  });
}

export function clearAdminToken() {
  adminToken = "";
}

export function getAdminToken() {
  return adminToken;
}
