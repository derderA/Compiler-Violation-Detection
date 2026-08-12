import { requireAdmin, clearAdminToken, getAdminToken } from "./auth.js";

const changePasswordForm = document.querySelector("#change-password-form");
const changePasswordStatus = document.querySelector("#change-password-status");
const currentPasswordInput = document.querySelector("#current-password");
const newPasswordInput = document.querySelector("#new-password");
const changePasswordBtn = document.querySelector("#change-password-btn");
const logoutBtn = document.querySelector("#password-logout");

function setStatus(message, isError = false) {
  changePasswordStatus.classList.remove("hidden");
  changePasswordStatus.textContent = message;
  changePasswordStatus.style.color = isError ? "#fda4af" : "#cbd5e1";
}

logoutBtn.addEventListener("click", () => {
  clearAdminToken();
  location.reload();
});

changePasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("正在修改...");
  changePasswordBtn.disabled = true;
  changePasswordBtn.textContent = "修改中...";
  try {
    const response = await fetch("/api/admin/change-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getAdminToken()}`,
      },
      body: JSON.stringify({
        currentPassword: currentPasswordInput.value,
        newPassword: newPasswordInput.value,
      }),
    });

    const data = await response.json();
    if (response.status === 401) {
      clearAdminToken();
      location.reload();
      return;
    }
    if (!response.ok) {
      throw new Error(data.error ?? "修改失败");
    }

    setStatus("密码已更新，正在重新登录...");
    changePasswordForm.reset();
    clearAdminToken();
    window.setTimeout(() => location.reload(), 1200);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "修改失败", true);
  } finally {
    changePasswordBtn.disabled = false;
    changePasswordBtn.textContent = "确认修改";
  }
});

await requireAdmin();
