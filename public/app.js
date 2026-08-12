const form = document.querySelector("#audit-form");
const submitBtn = document.querySelector("#submit-btn");
const statusCard = document.querySelector("#status-card");
const statusText = document.querySelector("#status-text");
const resultCard = document.querySelector("#result-card");
const resultMeta = document.querySelector("#result-meta");
const summaryAuditId = document.querySelector("#summary-audit-id");
const summaryBranch = document.querySelector("#summary-branch");
const summaryRepoUrl = document.querySelector("#summary-repo-url");
const hashValue = document.querySelector("#hash-value");
const reportPreview = document.querySelector("#report-preview");
const downloadReport = document.querySelector("#download-report");
const downloadHash = document.querySelector("#download-hash");
const copyHashBtn = document.querySelector("#copy-hash");

function setStatus(message, isError = false) {
  statusCard.classList.remove("hidden");
  statusText.textContent = message;
  statusText.style.color = isError ? "#fda4af" : "#cbd5e1";
}

function setLoading(loading) {
  submitBtn.disabled = loading;
  submitBtn.textContent = loading ? "审核中..." : "开始审核";
}

function resetCopyState() {
  copyHashBtn.textContent = "复制";
}

async function copyHashValue() {
  const value = hashValue.textContent.trim();
  if (!value) {
    return;
  }

  try {
    await navigator.clipboard.writeText(value);
    copyHashBtn.textContent = "已复制";
  } catch {
    copyHashBtn.textContent = "复制失败";
  }

  window.setTimeout(resetCopyState, 1800);
}

copyHashBtn.addEventListener("click", () => {
  void copyHashValue();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resultCard.classList.add("hidden");
  resetCopyState();

  const formData = new FormData(form);
  const payload = {
    repoUrl: String(formData.get("repoUrl") ?? "").trim(),
    branch: String(formData.get("branch") ?? "").trim(),
    gitlabToken: String(formData.get("gitlabToken") ?? "").trim(),
  };

  setLoading(true);
  setStatus("后端正在拉取仓库、扫描代码并调用 DeepSeek 生成审核报告，请稍候...");

  try {
    const response = await fetch("/api/audit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error ?? "审核失败");
    }

    resultCard.classList.remove("hidden");
    resultMeta.textContent = `审核编号：${data.auditId} | 分支：${data.branch} | 仓库：${data.repoUrl}`;
    summaryAuditId.textContent = data.auditId;
    summaryBranch.textContent = data.branch;
    summaryRepoUrl.textContent = data.repoUrl;
    hashValue.textContent = data.reportHashHex;
    reportPreview.textContent = data.reportMarkdown;
    downloadReport.href = data.reportDownloadUrl;
    downloadHash.href = data.hashDownloadUrl;
    setStatus("审核完成，报告和摘要值已生成。");
  } catch (error) {
    const message = error instanceof Error ? error.message : "审核失败";
    setStatus(message, true);
  } finally {
    setLoading(false);
  }
});

// ---- 管理员验证 ----
const adminLoginPanel = document.querySelector("#admin-login-panel");
const adminVerifyPanel = document.querySelector("#admin-verify-panel");
const adminLoginForm = document.querySelector("#admin-login-form");
const adminLoginStatus = document.querySelector("#admin-login-status");
const adminPasswordInput = document.querySelector("#admin-password");
const adminVerifyForm = document.querySelector("#admin-verify-form");
const verifyFile = document.querySelector("#verify-file");
const verifyDigest = document.querySelector("#verify-digest");
const verifyResult = document.querySelector("#verify-result");
const verifyBtn = document.querySelector("#verify-btn");
const adminLogoutBtn = document.querySelector("#admin-logout");
const changePasswordForm = document.querySelector("#change-password-form");
const changePasswordStatus = document.querySelector("#change-password-status");
const currentPasswordInput = document.querySelector("#current-password");
const newPasswordInput = document.querySelector("#new-password");
const changePasswordBtn = document.querySelector("#change-password-btn");

let adminToken = "";

function showAdminVerifyPanel() {
  adminLoginPanel.classList.add("hidden");
  adminVerifyPanel.classList.remove("hidden");
}

function showAdminLoginPanel() {
  adminToken = "";
  adminVerifyPanel.classList.add("hidden");
  adminLoginPanel.classList.remove("hidden");
  adminLoginStatus.classList.add("hidden");
  verifyResult.classList.add("hidden");
  changePasswordStatus.classList.add("hidden");
  adminVerifyForm.reset();
  changePasswordForm.reset();
}

function setAdminMessage(element, message, isError = false) {
  element.classList.remove("hidden");
  element.textContent = message;
  element.style.color = isError ? "#fda4af" : "#cbd5e1";
}

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

async function postJson(url, payload, token = "") {
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  let data = {};
  try {
    data = await response.json();
  } catch {
    // 忽略非 JSON 响应
  }
  return { response, data };
}

adminLoginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setAdminMessage(adminLoginStatus, "正在登录...");
  try {
    const { response, data } = await postJson("/api/admin/login", {
      password: adminPasswordInput.value,
    });
    if (!response.ok) {
      throw new Error(data.error ?? "登录失败");
    }
    adminToken = data.token;
    adminPasswordInput.value = "";
    showAdminVerifyPanel();
  } catch (error) {
    setAdminMessage(adminLoginStatus, error instanceof Error ? error.message : "登录失败", true);
  }
});

adminLogoutBtn.addEventListener("click", () => {
  showAdminLoginPanel();
});

adminVerifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  verifyResult.classList.add("hidden");

  const file = verifyFile.files[0];
  const digest = verifyDigest.value.trim();

  if (!file) {
    verifyResult.classList.remove("hidden");
    verifyResult.className = "verify-result verify-bad";
    verifyResult.textContent = "请先选择需要验证的文件";
    return;
  }
  if (!digest) {
    verifyResult.classList.remove("hidden");
    verifyResult.className = "verify-result verify-bad";
    verifyResult.textContent = "请输入文件处理后的摘要值";
    return;
  }

  verifyBtn.disabled = true;
  verifyBtn.textContent = "验证中...";
  try {
    const contentBase64 = await fileToBase64(file);
    const { response, data } = await postJson(
      "/api/admin/verify",
      { digest, contentBase64, fileName: file.name },
      adminToken
    );

    if (response.status === 401) {
      showAdminLoginPanel();
      throw new Error("登录已过期，请重新登录");
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
    verifyResult.classList.remove("hidden");
    verifyResult.className = "verify-result verify-bad";
    verifyResult.textContent = error instanceof Error ? error.message : "验证失败";
  } finally {
    verifyBtn.disabled = false;
    verifyBtn.textContent = "开始验证";
  }
});

changePasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setAdminMessage(changePasswordStatus, "正在修改...");
  changePasswordBtn.disabled = true;
  changePasswordBtn.textContent = "修改中...";
  try {
    const { response, data } = await postJson(
      "/api/admin/change-password",
      {
        currentPassword: currentPasswordInput.value,
        newPassword: newPasswordInput.value,
      },
      adminToken
    );

    if (response.status === 401) {
      showAdminLoginPanel();
      throw new Error("登录已过期，请重新登录");
    }
    if (!response.ok) {
      throw new Error(data.error ?? "修改失败");
    }

    showAdminLoginPanel();
    setAdminMessage(adminLoginStatus, "密码已更新，请重新登录。");
  } catch (error) {
    setAdminMessage(changePasswordStatus, error instanceof Error ? error.message : "修改失败", true);
  } finally {
    changePasswordBtn.disabled = false;
    changePasswordBtn.textContent = "确认修改";
  }
});
