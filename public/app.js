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
