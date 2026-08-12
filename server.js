import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import fsp from "node:fs/promises";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DOTENV_PATH = path.join(__dirname, ".env");

function loadDotEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const content = fs.readFileSync(filePath, "utf-8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const separatorIndex = line.indexOf("=");
    if (separatorIndex <= 0) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    if (!key || process.env[key] !== undefined) {
      continue;
    }

    let value = line.slice(separatorIndex + 1).trim();
    if (
      (value.startsWith("\"") && value.endsWith("\"")) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadDotEnv(DOTENV_PATH);

const HOST = process.env.HOST ?? "0.0.0.0";
const PORT = Number(process.env.PORT ?? 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
const REPORTS_DIR = path.join(__dirname, "reports");
const WORKSPACE_DIR = path.join(__dirname, "workspace");
const RULES_PATH = "违规说明.md";
const DEEPSEEK_BASE_URL = process.env.DEEPSEEK_BASE_URL ?? "https://api.deepseek.com";

const TEXT_FILE_EXTENSIONS = new Set([
  ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh",
  ".py", ".java", ".js", ".jsx", ".ts", ".tsx",
  ".go", ".rs", ".kt", ".swift", ".cs", ".php", ".rb",
  ".sh", ".cmake", ".txt", ".md", ".json", ".yaml", ".yml",
  ".toml", ".ini", ".cfg", ".gradle", ".xml"
]);

const IGNORED_DIR_NAMES = new Set([
  ".git", "node_modules", "build", "dist", "target", "out",
  ".idea", ".vscode", "__pycache__", ".next", ".nuxt"
]);

const SUSPICIOUS_PATTERNS = [
  {
    name: "命中特定样例名或测试点标识",
    rule: "违规说明 §三.1/§三.2/§三.3",
    regex: /\b(01_mm[123]?|h-4-0[123]|huffman-0[123]|transpose[012]|knapsack_naive-[123]|mm[123]?|transpose|knapsack|huffman)\b/gi,
  },
  {
    name: "出现函数名或字符串匹配痕迹",
    rule: "违规说明 §三.1",
    regex: /\b(strcmp|strstr|find\s*\(|includes\s*\(|GetName|getName|function_name|func_name|callee_name)\b/g,
  },
  {
    name: "出现输入模式判断痕迹",
    rule: "违规说明 §三.3/§三.5",
    regex: /\b(getint|getarray|scanf|fscanf|cin|argv|argc|read)\b.{0,80}(==|!=|<=|>=|<|>)/g,
  },
  {
    name: "出现大量硬编码候选常量",
    rule: "违规说明 §三.2/§三.5",
    regex: /\b(2000|1000|998244353|65535|4096|1024)\b/g,
  },
];

function json(response, statusCode, payload) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload, null, 2));
}

function sendText(response, statusCode, body, contentType = "text/plain; charset=utf-8") {
  response.writeHead(statusCode, { "Content-Type": contentType });
  response.end(body);
}

function guessContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".md":
      return "text/markdown; charset=utf-8";
    case ".txt":
      return "text/plain; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

async function serveStatic(requestPath, response) {
  const safePath = requestPath === "/" ? "/index.html" : requestPath;
  const resolvedPath = path.normalize(path.join(PUBLIC_DIR, safePath));
  if (!resolvedPath.startsWith(PUBLIC_DIR)) {
    sendText(response, 403, "禁止访问");
    return;
  }

  try {
    const content = await fsp.readFile(resolvedPath);
    response.writeHead(200, { "Content-Type": guessContentType(resolvedPath) });
    response.end(content);
  } catch {
    sendText(response, 404, "页面不存在");
  }
}

async function parseJsonBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString("utf-8");
  if (!raw.trim()) {
    return {};
  }
  return JSON.parse(raw);
}

function createAuditId() {
  const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${timestamp}-${suffix}`;
}

function sanitizeAuditId(value) {
  if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
    throw new Error("非法的 auditId");
  }
  return value;
}

async function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: { ...process.env, ...(options.env ?? {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf-8");
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf-8");
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(new Error(`${command} ${args.join(" ")} 执行失败（exit=${code}）\n${stderr || stdout}`));
    });
  });
}

function ensureHttpsUrl(repoUrl) {
  let parsed;
  try {
    parsed = new URL(repoUrl);
  } catch {
    throw new Error("仓库地址不是合法 URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("当前版本仅支持 http/https GitLab 仓库地址");
  }

  return parsed;
}

function createCloneUrl(repoUrl, gitlabToken) {
  const parsed = ensureHttpsUrl(repoUrl);
  if (!gitlabToken) {
    return parsed.toString();
  }

  parsed.username = "oauth2";
  parsed.password = gitlabToken;
  return parsed.toString();
}

function stripCredentials(repoUrl) {
  const parsed = ensureHttpsUrl(repoUrl);
  parsed.username = "";
  parsed.password = "";
  return parsed.toString();
}

async function cloneRepository({ repoUrl, branch, gitlabToken, destination }) {
  const cloneUrl = createCloneUrl(repoUrl, gitlabToken);
  await runCommand("git", [
    "clone",
    "--depth", "1",
    "--single-branch",
    "--branch", branch,
    cloneUrl,
    destination,
  ]);
}

function isTextFile(fileName) {
  return TEXT_FILE_EXTENSIONS.has(path.extname(fileName).toLowerCase()) || path.basename(fileName) === "CMakeLists.txt";
}

async function walkFiles(rootDir, currentDir = rootDir, results = []) {
  const entries = await fsp.readdir(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && IGNORED_DIR_NAMES.has(entry.name)) {
      continue;
    }

    const absolutePath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      await walkFiles(rootDir, absolutePath, results);
      continue;
    }

    const relativePath = path.relative(rootDir, absolutePath);
    results.push({ absolutePath, relativePath });
  }
  return results;
}

function buildSnippet(lines, hitLineIndex, radius = 3) {
  const start = Math.max(0, hitLineIndex - radius);
  const end = Math.min(lines.length, hitLineIndex + radius + 1);
  const snippet = [];
  for (let i = start; i < end; i += 1) {
    snippet.push(`${String(i + 1).padStart(4, " ")} | ${lines[i]}`);
  }
  return snippet.join("\n");
}

async function scanRepository(repoDir) {
  const allFiles = await walkFiles(repoDir);
  const textFiles = allFiles.filter((file) => isTextFile(file.relativePath));

  const findings = [];
  const fileSummaries = [];

  for (const file of textFiles) {
    const stat = await fsp.stat(file.absolutePath);
    if (stat.size > 200 * 1024) {
      continue;
    }

    const content = await fsp.readFile(file.absolutePath, "utf-8");
    const lines = content.split(/\r?\n/);
    fileSummaries.push({
      path: file.relativePath,
      size: stat.size,
      lines: lines.length,
    });

    for (const pattern of SUSPICIOUS_PATTERNS) {
      const fileRegex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let lineIndex = 0;
      for (const line of lines) {
        fileRegex.lastIndex = 0;
        if (fileRegex.test(line)) {
          findings.push({
            file: file.relativePath,
            line: lineIndex + 1,
            pattern: pattern.name,
            rule: pattern.rule,
            snippet: buildSnippet(lines, lineIndex),
          });
        }
        lineIndex += 1;
      }
    }
  }

  const topFindings = findings.slice(0, 18);
  const suspiciousPaths = [...new Set(topFindings.map((item) => item.file))];
  const selectedFiles = [];
  let totalChars = 0;

  for (const relativePath of suspiciousPaths) {
    const absolutePath = path.join(repoDir, relativePath);
    const content = await fsp.readFile(absolutePath, "utf-8");
    const trimmed = content.slice(0, 10000);
    if (totalChars + trimmed.length > 60000) {
      break;
    }
    selectedFiles.push({ path: relativePath, content: trimmed });
    totalChars += trimmed.length;
  }

  if (selectedFiles.length === 0) {
    for (const file of fileSummaries.slice(0, 6)) {
      const absolutePath = path.join(repoDir, file.path);
      const content = await fsp.readFile(absolutePath, "utf-8");
      const trimmed = content.slice(0, 8000);
      if (totalChars + trimmed.length > 60000) {
        break;
      }
      selectedFiles.push({ path: file.path, content: trimmed });
      totalChars += trimmed.length;
    }
  }

  return {
    fileCount: allFiles.length,
    textFileCount: fileSummaries.length,
    fileSummaries: fileSummaries.slice(0, 200),
    findings: topFindings,
    selectedFiles,
  };
}

function formatFindingsMarkdown(findings) {
  if (findings.length === 0) {
    return "- 未发现明显的程序化命中线索，但这不代表仓库一定合规，仍需结合 DeepSeek 审核结果判断。";
  }

  return findings.map((finding, index) => (
    `${index + 1}. ${finding.pattern}（${finding.rule}）\n` +
    `   - 文件：\`${finding.file}\`\n` +
    `   - 代码片段：\n\n` +
    "```text\n" +
    `${finding.snippet}\n` +
    "```"
  )).join("\n\n");
}

function buildPrompt({ repoUrl, branch, rulesMarkdown, scanResult }) {
  const fileSummaryText = scanResult.fileSummaries
    .slice(0, 80)
    .map((file) => `- ${file.path} (${file.lines} 行, ${file.size} bytes)`)
    .join("\n");

  const findingsText = scanResult.findings.length === 0
    ? "没有程序化扫描到明显嫌疑点。"
    : scanResult.findings.map((finding, index) => (
        `${index + 1}. [${finding.rule}] ${finding.pattern}\n` +
        `文件: ${finding.file}:${finding.line}\n` +
        `${finding.snippet}`
      )).join("\n\n");

  const fileContexts = scanResult.selectedFiles
    .map((file) => (
      `文件: ${file.path}\n` +
      "```text\n" +
      `${file.content}\n` +
      "```"
    ))
    .join("\n\n");

  return [
    "你是编译器比赛违规审核助手，请严格按照给定规则审核 GitLab 仓库。",
    "审核时必须遵守：",
    "1. 只能依据提供的规则和代码证据判断，不要凭空猜测。",
    "2. 区分“明确违规证据”“高风险可疑点”“暂未发现证据”。",
    "3. 如果证据不足，不要下定罪结论，要明确写“建议人工复核”。",
    "4. 输出必须是 Markdown，且必须包含以下章节：",
    "   - 审核结论",
    "   - 风险等级",
    "   - 触犯或疑似触犯的规则条款",
    "   - 证据分析",
    "   - 是否建议人工复核",
    "   - 审核建议",
    "",
    `仓库地址：${repoUrl}`,
    `分支：${branch}`,
    "",
    "【违规说明原文】",
    rulesMarkdown,
    "",
    "【仓库文件概览】",
    fileSummaryText || "- 无",
    "",
    "【程序化扫描线索】",
    findingsText,
    "",
    "【重点文件内容】",
    fileContexts || "无可用重点文件内容。",
    "",
    "请直接输出 Markdown 报告正文，不要额外输出 JSON。",
  ].join("\n");
}

async function callDeepSeek({ apiKey, prompt }) {
  const response = await fetch(`${DEEPSEEK_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "deepseek-chat",
      temperature: 0.1,
      messages: [
        {
          role: "system",
          content: "你是严谨的代码审计助手，只能依据给定规则和证据输出 Markdown 审核报告。",
        },
        {
          role: "user",
          content: prompt,
        },
      ],
    }),
    signal: AbortSignal.timeout(120000),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`DeepSeek API 调用失败：${response.status} ${errorText}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content?.trim() ?? "DeepSeek 未返回有效内容。";
}

function buildFinalReport({ repoUrl, branch, auditId, rulesPath, scanResult, aiMarkdown }) {
  return [
    "# GitLab 仓库违规审核报告",
    "",
    `- 审核编号：\`${auditId}\``,
    `- 仓库地址：\`${repoUrl}\``,
    `- 分支：\`${branch}\``,
    `- 规则来源：\`${rulesPath}\``,
    `- 审核时间：${new Date().toLocaleString("zh-CN", { hour12: false })}`,
    "",
    "## 程序化扫描概览",
    "",
    `- 扫描文件总数：${scanResult.fileCount}`,
    `- 文本/代码文件数：${scanResult.textFileCount}`,
    `- 程序化线索数：${scanResult.findings.length}`,
    "",
    "## 程序化扫描线索",
    "",
    formatFindingsMarkdown(scanResult.findings),
    "",
    "## DeepSeek 审核结论",
    "",
    aiMarkdown,
    "",
    "## 说明",
    "",
    "- 本报告先进行程序化扫描，再将规则、仓库摘要和重点代码交给 DeepSeek 生成审核结论。",
    "- 哈希值针对本 Markdown 报告全文计算，可用于后续校验报告是否被篡改。",
    "",
  ].join("\n");
}

async function writeAuditArtifacts({ auditId, reportMarkdown, reportHashHex, metadata }) {
  const auditDir = path.join(REPORTS_DIR, auditId);
  await fsp.mkdir(auditDir, { recursive: true });

  const reportPath = path.join(auditDir, "analysis.md");
  const hashPath = path.join(auditDir, "hash.txt");
  const metadataPath = path.join(auditDir, "metadata.json");

  await fsp.writeFile(reportPath, reportMarkdown, "utf-8");
  await fsp.writeFile(
    hashPath,
    [
      reportHashHex,
      "",
    ].join("\n"),
    "utf-8"
  );
  await fsp.writeFile(metadataPath, JSON.stringify(metadata, null, 2), "utf-8");

  return { reportPath, hashPath, metadataPath };
}

async function removeDirectory(targetDir) {
  await fsp.rm(targetDir, { recursive: true, force: true });
}

async function handleAudit(request, response) {
  const body = await parseJsonBody(request);
  const repoUrl = String(body.repoUrl ?? "").trim();
  const branch = String(body.branch ?? "").trim() || "main";
  const gitlabToken = String(body.gitlabToken ?? "").trim();

  if (!repoUrl) {
    json(response, 400, { error: "请填写 GitLab 仓库地址" });
    return;
  }

  if (!branch) {
    json(response, 400, { error: "请填写分支名" });
    return;
  }

  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey) {
    json(response, 500, { error: "服务端未配置 DEEPSEEK_API_KEY" });
    return;
  }

  const rulesMarkdown = await fsp.readFile(RULES_PATH, "utf-8");
  const auditId = createAuditId();
  const workspaceDir = path.join(WORKSPACE_DIR, auditId);
  const repoDir = path.join(workspaceDir, "repo");

  await fsp.mkdir(workspaceDir, { recursive: true });

  try {
    const sanitizedRepoUrl = stripCredentials(repoUrl);
    await cloneRepository({ repoUrl, branch, gitlabToken, destination: repoDir });
    const scanResult = await scanRepository(repoDir);
    const prompt = buildPrompt({
      repoUrl: sanitizedRepoUrl,
      branch,
      rulesMarkdown,
      scanResult,
    });
    const aiMarkdown = await callDeepSeek({ apiKey, prompt });
    const reportMarkdown = buildFinalReport({
      repoUrl: sanitizedRepoUrl,
      branch,
      auditId,
      rulesPath: RULES_PATH,
      scanResult,
      aiMarkdown,
    });

    const reportHash = crypto.createHash("sha256").update(reportMarkdown, "utf-8").digest();
    const reportHashHex = reportHash.toString("hex");

    await writeAuditArtifacts({
      auditId,
      reportMarkdown,
      reportHashHex,
      metadata: {
        auditId,
        repoUrl: sanitizedRepoUrl,
        branch,
        generatedAt: new Date().toISOString(),
        findings: scanResult.findings.length,
      },
    });

    json(response, 200, {
      auditId,
      repoUrl: sanitizedRepoUrl,
      branch,
      reportMarkdown,
      reportHashHex,
      reportDownloadUrl: `/api/download/${auditId}/analysis.md`,
      hashDownloadUrl: `/api/download/${auditId}/hash.txt`,
    });
  } catch (error) {
    json(response, 500, {
      error: error instanceof Error ? error.message : "审核失败",
    });
  } finally {
    await removeDirectory(workspaceDir);
  }
}

async function handleDownload(requestPath, response) {
  const parts = requestPath.split("/").filter(Boolean);
  const auditId = sanitizeAuditId(parts[2] ?? "");
  const fileName = parts[3] ?? "";
  if (!["analysis.md", "hash.txt", "metadata.json"].includes(fileName)) {
    sendText(response, 404, "文件不存在");
    return;
  }

  const targetPath = path.join(REPORTS_DIR, auditId, fileName);
  try {
    const content = await fsp.readFile(targetPath);
    response.writeHead(200, {
      "Content-Type": guessContentType(targetPath),
      "Content-Disposition": `attachment; filename="${fileName}"`,
    });
    response.end(content);
  } catch {
    sendText(response, 404, "文件不存在");
  }
}

const server = http.createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);

    if (request.method === "GET" && requestUrl.pathname === "/api/health") {
      json(response, 200, { ok: true });
      return;
    }

    if (request.method === "POST" && requestUrl.pathname === "/api/audit") {
      await handleAudit(request, response);
      return;
    }

    if (request.method === "GET" && requestUrl.pathname.startsWith("/api/download/")) {
      await handleDownload(requestUrl.pathname, response);
      return;
    }

    if (request.method === "GET") {
      await serveStatic(requestUrl.pathname, response);
      return;
    }

    sendText(response, 405, "不支持的请求方法");
  } catch (error) {
    json(response, 500, {
      error: error instanceof Error ? error.message : "服务器内部错误",
    });
  }
});

server.listen(PORT, HOST, async () => {
  await Promise.all([
    fsp.mkdir(REPORTS_DIR, { recursive: true }),
    fsp.mkdir(WORKSPACE_DIR, { recursive: true }),
  ]);
  console.log(`GitLab 违规审核工具已启动：http://${HOST}:${PORT}`);
});
