import { requireAdmin, clearAdminToken, getAdminToken } from "./auth.js";

const verifyForm = document.querySelector("#verify-form");
const verifyFile = document.querySelector("#verify-file");
const verifyDigest = document.querySelector("#verify-digest");
const verifyResult = document.querySelector("#verify-result");
const verifyBtn = document.querySelector("#verify-btn");
const logoutBtn = document.querySelector("#verify-logout");

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== "string") {
        reject(new Error("文件读取失败"));
        return;
      }
      const commaIndex = result.indexOf(",");
      resolve(commaIndex === -1 ? result : result.slice(commaIndex + 1));
    };
    reader.onerror = () => reject(new Error("文件读取失败"));
    reader.readAsDataURL(file);
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showError(message) {
  verifyResult.classList.remove("hidden");
  verifyResult.className = "verify-result verify-bad";
  verifyResult.textContent = message;
}

logoutBtn.addEventListener("click", () => {
  clearAdminToken();
  location.reload();
});

verifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  verifyResult.classList.add("hidden");

  const file = verifyFile.files[0];
  const digest = verifyDigest.value.trim();

  if (!file) {
    showError("请先选择需要验证的文件");
    return;
  }
  if (!digest) {
    showError("请输入文件处理后的摘要值");
    return;
  }

  verifyBtn.disabled = true;
  verifyBtn.textContent = "验证中...";
  try {
    const contentBase64 = await fileToBase64(file);
    const response = await fetch("/api/admin/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getAdminToken()}`,
      },
      body: JSON.stringify({ digest, contentBase64, fileName: file.name }),
    });

    const data = await response.json();
    if (response.status === 401) {
      clearAdminToken();
      location.reload();
      return;
    }
    if (!response.ok) {
      throw new Error(data.error ?? "验证失败");
    }

    const isConsistent = data.consistent === true;
    verifyResult.classList.remove("hidden");
    verifyResult.className = `verify-result ${isConsistent ? "verify-ok" : "verify-bad"}`;
    verifyResult.innerHTML = [
      `<strong>验证结果：${isConsistent ? "一致" : "不一致"}</strong>`,
      `文件名：${escapeHtml(data.fileName)}`,
      `重新计算的摘要：<code>${escapeHtml(data.computedDigest)}</code>`,
      `输入的摘要：<code>${escapeHtml(data.providedDigest)}</code>`,
    ].join("<br />");
  } catch (error) {
    showError(error instanceof Error ? error.message : "验证失败");
  } finally {
    verifyBtn.disabled = false;
    verifyBtn.textContent = "开始验证";
  }
});

await requireAdmin();
