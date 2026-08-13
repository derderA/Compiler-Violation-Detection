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
const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL ?? "deepseek-v4-pro";
const DEEPSEEK_MAX_INPUT_TOKENS = Number(process.env.DEEPSEEK_MAX_INPUT_TOKENS ?? 300000);
const DEEPSEEK_MAX_OUTPUT_TOKENS = Number(process.env.DEEPSEEK_MAX_OUTPUT_TOKENS ?? 65536);
const DEEPSEEK_TIMEOUT_MS = Number(process.env.DEEPSEEK_TIMEOUT_MS ?? 600000);
const FILE_HEAD_LINES = 40;
const DOC_HEAD_LINES = 150;
const HMAC_SECRET = process.env.HMAC_SECRET ?? "";
const DEFAULT_ADMIN_PASSWORD = "admin123";
const ADMIN_TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const DB_PATH = path.join(__dirname, "data", "db.json");

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

function hmacDigestHex(content) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(content).digest("hex");
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function signAdminToken() {
  const payload = { sub: "admin", exp: Date.now() + ADMIN_TOKEN_TTL_MS };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", `admin-token:${HMAC_SECRET}`)
    .update(body)
    .digest("base64url");
  return `${body}.${signature}`;
}

function verifyAdminToken(token) {
  if (typeof token !== "string" || !token.includes(".")) {
    return false;
  }

  const separatorIndex = token.lastIndexOf(".");
  const body = token.slice(0, separatorIndex);
  const signature = token.slice(separatorIndex + 1);
  const expected = crypto
    .createHmac("sha256", `admin-token:${HMAC_SECRET}`)
    .update(body)
    .digest("base64url");

  if (!safeEqual(signature, expected)) {
    return false;
  }

  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf-8"));
    return payload.sub === "admin" && typeof payload.exp === "number" && payload.exp > Date.now();
  } catch {
    return false;
  }
}

function readBearerToken(request) {
  const authorization = String(request.headers.authorization ?? "");
  if (!authorization.startsWith("Bearer ")) {
    return "";
  }
  return authorization.slice("Bearer ".length).trim();
}

function hashPassword(password, salt = crypto.randomBytes(16)) {
  const hash = crypto.scryptSync(password, salt, 64);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}

function verifyPassword(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(password, salt, 64);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

async function readDb() {
  try {
    const raw = await fsp.readFile(DB_PATH, "utf-8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function writeDb(db) {
  await fsp.mkdir(path.dirname(DB_PATH), { recursive: true });
  await fsp.writeFile(DB_PATH, JSON.stringify(db, null, 2), "utf-8");
}

async function ensureAdminInitialized() {
  const db = await readDb();
  if (db?.admin?.salt && db?.admin?.passwordHash) {
    if (typeof db.admin.mustChangePassword !== "boolean") {
      db.admin.mustChangePassword = true;
      await writeDb(db);
    }
    return { created: false };
  }

  const { salt, hash } = hashPassword(DEFAULT_ADMIN_PASSWORD);
  await writeDb({
    ...(db ?? {}),
    admin: {
      salt,
      passwordHash: hash,
      mustChangePassword: true,
      updatedAt: new Date().toISOString(),
    },
  });
  return { created: true };
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

function isDocumentationFile(relativePath) {
  const base = path.basename(relativePath).toLowerCase();
  const dir = path.dirname(relativePath);
  if (dir !== "." && dir !== "/" && dir !== "") {
    return false;
  }
  return /(readme|design|report|doc|spec|说明|设计|文档|报告|项目|介绍|优化)/.test(base) ||
    /\.(md|txt|rst)$/.test(base);
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

async function collectRepository(repoDir) {
  const allFiles = await walkFiles(repoDir);
  const textFiles = allFiles.filter((file) => isTextFile(file.relativePath));

  const files = [];
  for (const file of textFiles) {
    let stat;
    try {
      stat = await fsp.stat(file.absolutePath);
    } catch {
      continue;
    }

    let lines = 0;
    let head = "";
    try {
      const content = await fsp.readFile(file.absolutePath, "utf-8");
      const fileLines = content.split(/\r?\n/);
      lines = fileLines.length;
      const headLimit = isDocumentationFile(file.relativePath) ? DOC_HEAD_LINES : FILE_HEAD_LINES;
      head = fileLines.slice(0, headLimit).join("\n");
    } catch {
      // 无法按文本读取的文件仅记录元信息，不参与后续分析
    }

    files.push({
      absolutePath: file.absolutePath,
      relativePath: file.relativePath,
      size: stat.size,
      lines,
      head,
    });
  }

  return {
    fileCount: allFiles.length,
    textFileCount: files.length,
    files,
  };
}

function estimateTokens(text) {
  // 保守估算：代码多为 ASCII，规则/说明含中文，取约 1 token / 3 字符
  return Math.ceil(String(text ?? "").length / 3);
}

function extractJson(text) {
  if (!text) {
    return null;
  }
  let source = String(text).trim();
  const fence = source.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    source = fence[1].trim();
  }

  const closers = { "{": "}", "[": "]" };
  let openIndex = -1;
  let openChar = "";
  for (const ch of ["{", "["]) {
    const idx = source.indexOf(ch);
    if (idx !== -1 && (openIndex === -1 || idx < openIndex)) {
      openIndex = idx;
      openChar = ch;
    }
  }
  if (openIndex === -1) {
    return null;
  }

  const closeChar = closers[openChar];
  const closeIndex = source.lastIndexOf(closeChar);
  if (closeIndex === -1 || closeIndex <= openIndex) {
    return null;
  }
  try {
    return JSON.parse(source.slice(openIndex, closeIndex + 1));
  } catch {
    return null;
  }
}

function buildFileManifest(files, budgetTokens = DEEPSEEK_MAX_INPUT_TOKENS) {
  const docFiles = files.filter((file) => isDocumentationFile(file.relativePath));
  const otherFiles = files.filter((file) => !isDocumentationFile(file.relativePath));
  const ordered = [...docFiles, ...otherFiles];

  for (const headLines of [40, 20, 10, 5, 1]) {
    const entries = [];
    let used = 0;
    for (const file of ordered) {
      const isDoc = isDocumentationFile(file.relativePath);
      // 文档文件用完整存储的 head（较长），其余文件按当前档位截断
      const head = isDoc
        ? file.head
        : (headLines === 1 ? "" : file.head.split(/\r?\n/).slice(0, headLines).join("\n"));
      const label = isDoc ? "【项目文档】" : "";
      const entry = `- ${label}${file.relativePath} (${file.lines} 行, ${file.size} bytes)${head ? "\n" + head : ""}`;
      const cost = estimateTokens(entry);
      if (used + cost > budgetTokens) {
        break;
      }
      entries.push(entry);
      used += cost;
    }
    if (entries.length > 0) {
      return entries.join("\n\n");
    }
  }
  return ordered.slice(0, 200).map((file) => `- ${file.relativePath} (${file.lines} 行)`).join("\n");
}

async function readPassSources(pass, files, budgetTokens = DEEPSEEK_MAX_INPUT_TOKENS) {
  const fileMap = new Map(files.map((file) => [file.relativePath, file]));
  const referenced = (pass.files ?? []).map((item) => String(item).trim()).filter(Boolean);
  const sources = [];
  let used = 0;

  for (const relativePath of referenced) {
    const meta = fileMap.get(relativePath);
    if (!meta) {
      continue;
    }

    let content = "";
    try {
      content = await fsp.readFile(meta.absolutePath, "utf-8");
    } catch {
      continue;
    }

    const contentTokens = estimateTokens(content);
    const remaining = budgetTokens - used;
    if (remaining <= 0) {
      break;
    }

    let truncated = false;
    if (contentTokens > remaining) {
      content = content.slice(0, Math.floor(remaining * 3));
      truncated = true;
    }

    sources.push({ path: relativePath, content, truncated });
    used += estimateTokens(content);
  }

  return sources;
}

const SYSY_RUNTIME_NOTE = [
  "【审核口径补充：关于 SysY 标准运行时库 sylib】",
  "SysY 语言有标准运行时库（sylib），其 I/O 与计时函数如 putint、putch、putfloat、putarray、putfarray、getint、getch、getfloat、getarray、getfarray、_sysy_starttime、_sysy_stoptime、starttime、stoptime 等是语言标准定义的库函数。",
  "编译器识别这些「标准运行时库函数」以判断其是否无副作用/纯，从而安全地进行 Mem2Reg、别名分析、死代码消除等优化，属于通用优化，不构成违规。",
  "只有识别「具体测试用例特有」的函数名、字符串、输入大小/内容等特征（如特定样例名、测试点标识、特定用户函数）来做针对性优化，才属于违规。",
].join("\n");

const STATIC_CONDITION_NOTE = [
  "【审核口径补充：编译期结构条件 vs 运行时输入特判】",
  "1. 编译期静态结构条件（如循环边界/trip count 为编译期常量、满足某种指令或基本块结构、函数无副作用等）是通用优化的正常前提，属于合理性优化，不违规；",
  "2. 运行时输入特判（根据实际读入数据的大小/内容/字符串在运行时激活特定优化路径、硬编码某个具体测试用例的结果）才属于 §三.2/§三.3 的违规。",
  "循环展开按固定因子展开、并要求边界为编译期常量且可被因子整除（否则跳过），属于灰色地带的通用优化，一般判「合规」，除非有明显证据表明其针对特定测试用例的数值做了调优。",
].join("\n");

const HARDWARE_NOTE = [
  "【审核口径补充：目标硬件特性 vs 竞赛测试规模】",
  "编译器针对目标处理器（如 ARM Cortex-A53）的缓存大小/缓存行/路数、寄存器数量、流水线、指令集等硬件特性设置的常量或参数（如循环分块的块大小、避免缓存冲突的 2^k+1 型常量、指令调度窗口等），属于《违规说明》§二『利用处理器硬件通用特性』的合理优化，不违规。",
  "判断一个常量是否违规，关键看它对应的是目标硬件的通用参数还是测试用例的输入规模：对应硬件参数（如 257=256+1 这种避免 cache 冲突的取值）应判合理；只有当常量明显对应特定测试用例的输入规模/数值时才判违规。即使注释中出现『竞赛/测试』字眼，只要数值本质是硬件参数，也应判合理。",
].join("\n");

function buildMapPrompt({ repoUrl, branch, manifest }) {
  return [
    "你是编译器工程结构分析助手。下面是一个编译器项目的文件清单，其中标注【项目文档】的是项目说明/设计/报告类文档，其余是源码文件（含每个文件开头若干行）。",
    "",
    "你的任务是完整识别出该编译器实现的所有『优化 / 代码变换 / 特判』pass，不要遗漏。请按以下步骤分析：",
    "",
    "1. 优先阅读【项目文档】——项目主目录或 docs/ 下通常有说明文档（README、设计文档、报告、说明等，命名可能各异），其中常会列出优化流水线与各 pass；把它当作权威参考，据此对照源码确认 pass。",
    "2. 结合目录结构定位 pass 代码——源码里通常有集中放置优化逻辑的目录或文件，但命名不固定（可能是 pass/passes/opt/transform/optimization/midend/优化 等目录，也可能是 PassManager/PassRegistry 之类的调度文件，或文件名含 Pass/Opt/Optimize 的文件）；请结合调度文件和文档自行判断，不要假设固定目录名。",
    "3. 逐个枚举所有优化 pass，包括但不限于：函数内联、循环变换（展开/交换/合并/不变量外提/向量化/归纳变量削减）、常量折叠与传播、死代码消除、公共子表达式消除、函数克隆/特化、Mem2Reg/SSA、寄存器分配、CFG 简化，以及任何『根据函数名/字符串/输入特征做特判』或『硬编码结果』的逻辑。",
    "",
    "要求：",
    "- 力求完整，宁可多列也不要漏掉常见 pass；",
    "- 每个 pass 必须在 files 字段里给出其对应的源文件相对路径（不要留空），functions 列出关键函数名；",
    "- 忽略纯前端、词法/语法分析、类型检查、代码生成等管道逻辑，除非其中夹带了优化/特判。",
    "",
    `仓库地址：${repoUrl}`,
    `分支：${branch}`,
    "",
    "【文件清单】",
    manifest,
    "",
    "请只输出一个合法 JSON 对象（不要 Markdown 代码围栏、不要额外说明），结构如下：",
    JSON.stringify({
      passes: [
        {
          name: "pass 名称",
          purpose: "一句话目的",
          files: ["相对路径"],
          functions: ["函数名"],
          confidence: "high|medium|low",
        },
      ],
      nonPassFiles: ["非 pass 相关文件路径"],
      notes: "补充说明",
    }, null, 2),
    "",
    "若没有识别到优化 pass，请输出 { \"passes\": [], \"nonPassFiles\": [], \"notes\": \"...\" }。",
  ].join("\n");
}

function estimatePassTokens(item) {
  const text = (item.sources ?? []).map((source) => source.content).join("\n");
  return estimateTokens(text) + estimateTokens(item.pass.name ?? "") + 60;
}

function packPassesIntoBatches(items, budgetTokens) {
  const batches = [];
  let current = [];
  let used = 0;
  for (const item of items) {
    const cost = estimatePassTokens(item);
    if (current.length > 0 && used + cost > budgetTokens) {
      batches.push(current);
      current = [];
      used = 0;
    }
    current.push(item);
    used += cost;
  }
  if (current.length > 0) {
    batches.push(current);
  }
  return batches;
}

function buildPassBatchPrompt({ batch, rulesMarkdown, batchIndex, batchCount }) {
  const sourceText = batch
    .map((item, index) => {
      const pass = item.pass;
      const sources = item.sources ?? [];
      const src = sources
        .map((source) => {
          const note = source.truncated
            ? `\n（该文件过大，已截断，仅展示前 ${source.content.length} 字符）`
            : "";
          return `文件: ${source.path}\n\`\`\`text\n${source.content}\n\`\`\`${note}`;
        })
        .join("\n\n");
      return [
        `### 第 ${index + 1} 个 pass：${pass.name ?? "未知"}`,
        `目的：${pass.purpose ?? "未知"}`,
        `涉及函数：${(pass.functions ?? []).join(", ") || "未知"}`,
        "",
        src || "（未找到该 pass 引用的文件，无法分析）",
      ].join("\n");
    })
    .join("\n\n");

  return [
    "你是编译器比赛违规审核助手。下面给出了多个优化 pass 的源代码，请逐个分析其原理并判定是否违规。",
    "",
    "审核原则：",
    "1. 只依据提供的规则与代码证据判断，不要凭空猜测；",
    "2. 区分『明确违规』『高风险可疑』『合规（通用优化）』；",
    "3. 关键判据：该 pass 是否依赖特定测试用例的特征（函数名、字符串、输入大小/内容等）来激活特定优化路径，而非通用优化；",
    "4. 证据不足时判『疑似违规』，不要下定罪结论；",
    "5. 每个 pass 的 principle 和 reasoning 请尽量简洁（各 2~4 句话），确保所有 pass 都能被完整输出。",
    "",
    `（共 ${batchCount} 批，本批为第 ${batchIndex + 1} 批）`,
    "",
    "【违规说明原文】",
    rulesMarkdown,
    "",
    "【审核口径补充】",
    SYSY_RUNTIME_NOTE,
    "",
    STATIC_CONDITION_NOTE,
    "",
    HARDWARE_NOTE,
    "",
    "【待分析的多个 pass】",
    sourceText,
    "",
    "请只输出一个 JSON 数组（不要 Markdown 代码围栏），数组元素顺序与上面 pass 顺序一一对应，每个元素结构如下：",
    JSON.stringify({
      passName: "pass 名称",
      principle: "该 pass 的优化原理（一段话）",
      verdict: "合规 | 疑似违规 | 违规",
      ruleClauses: ["§三.1", "§三.3"],
      evidence: [
        { file: "相对路径", line: 12, code: "关键代码行", reason: "为什么可疑" },
      ],
      confidence: "high|medium|low",
      reasoning: "判定理由",
    }, null, 2),
  ].join("\n");
}

function buildSynthesisPrompt({ repoUrl, branch, passResults, rulesMarkdown }) {
  const compact = passResults
    .map((passResult) => {
      if (passResult.error) {
        return `- ${passResult.passName ?? "未知"}：判定=分析失败，原因=${passResult.error}`;
      }
      const clauses = (passResult.ruleClauses ?? []).join("、") || "无";
      return `- ${passResult.passName ?? "未知"}：判定=${passResult.verdict ?? "未知"}，置信度=${passResult.confidence ?? "unknown"}，规则=${clauses}，理由=${passResult.reasoning ?? ""}`;
    })
    .join("\n");

  return [
    "你是编译器比赛违规审核助手。以下是逐个优化 pass 的分析结论，请据此输出整份仓库的总体审核结论。",
    "",
    `仓库地址：${repoUrl}`,
    `分支：${branch}`,
    "",
    "【违规说明原文】",
    rulesMarkdown,
    "",
    "【审核口径补充】",
    SYSY_RUNTIME_NOTE,
    "",
    STATIC_CONDITION_NOTE,
    "",
    HARDWARE_NOTE,
    "",
    "【各 pass 分析结论】",
    compact || "- 无",
    "",
    "请输出 Markdown 正文，必须包含以下章节：",
    "- 审核结论",
    "- 风险等级（高/中/低）",
    "- 触犯或疑似触犯的规则条款",
    "- 是否建议人工复核",
    "- 审核建议",
    "",
    "只输出 Markdown 正文，不要输出 JSON。",
  ].join("\n");
}

async function callDeepSeek({ apiKey, prompt, system = "你是严谨的代码审计助手，只能依据给定规则和证据输出分析结果。", timeoutMs = DEEPSEEK_TIMEOUT_MS }) {
  const response = await fetch(`${DEEPSEEK_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: DEEPSEEK_MODEL,
      temperature: 0.1,
      max_tokens: DEEPSEEK_MAX_OUTPUT_TOKENS,
      messages: [
        { role: "system", content: system },
        { role: "user", content: prompt },
      ],
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`DeepSeek API 调用失败：${response.status} ${errorText}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content?.trim() ?? "DeepSeek 未返回有效内容。";
}

async function callDeepSeekJson({ apiKey, prompt, system, timeoutMs }) {
  const first = await callDeepSeek({ apiKey, prompt, system, timeoutMs });
  const parsed = extractJson(first);
  if (parsed) {
    return parsed;
  }

  const retryPrompt = `${prompt}\n\n注意：请务必只输出一个合法 JSON 对象，不要包含 Markdown 代码围栏或任何额外说明文字。`;
  const second = await callDeepSeek({ apiKey, prompt: retryPrompt, system, timeoutMs });
  const retryParsed = extractJson(second);
  if (retryParsed) {
    return retryParsed;
  }

  throw new Error("DeepSeek 未返回可解析的 JSON");
}

function formatPassSection(passResult, index) {
  if (passResult.error) {
    return [
      `### Pass ${index + 1}：${passResult.passName ?? "未知"}`,
      "",
      "- 判定：分析失败",
      "",
      `- 原因：${passResult.error}`,
      "",
    ].join("\n");
  }

  const lines = [
    `### Pass ${index + 1}：${passResult.passName ?? "未知"}`,
    "",
    `- 判定：**${passResult.verdict ?? "未知"}**（置信度：${passResult.confidence ?? "unknown"}）`,
    `- 对应规则条款：${(passResult.ruleClauses ?? []).join("、") || "无"}`,
    "",
    "#### 原理",
    "",
    passResult.principle ?? "（无）",
    "",
    "#### 证据",
    "",
  ];

  if ((passResult.evidence ?? []).length === 0) {
    lines.push("- 无明确证据行", "");
  } else {
    for (const ev of passResult.evidence) {
      lines.push(`- \`${ev.file}\` 第 ${ev.line} 行`, "", "```text", ev.code ?? "", "```", "", `  - ${ev.reason ?? ""}`, "");
    }
  }

  lines.push("#### 判定理由", "", passResult.reasoning ?? "（无）", "");
  return lines.join("\n");
}

function buildFinalReport({ repoUrl, branch, auditId, rulesPath, collectResult, passResults, synthesisMarkdown }) {
  const passSections = passResults.map(formatPassSection).join("\n");
  const violationCount = passResults.filter((passResult) => passResult.verdict === "违规").length;
  const suspectCount = passResults.filter((passResult) => passResult.verdict === "疑似违规").length;

  return [
    "# GitLab 仓库违规审核报告",
    "",
    `- 审核编号：\`${auditId}\``,
    `- 仓库地址：\`${repoUrl}\``,
    `- 分支：\`${branch}\``,
    `- 规则来源：\`${rulesPath}\``,
    `- 审核时间：${new Date().toLocaleString("zh-CN", { hour12: false })}`,
    "",
    "## 扫描概览",
    "",
    `- 扫描文件总数：${collectResult.fileCount}`,
    `- 文本/代码文件数：${collectResult.textFileCount}`,
    `- 识别到的优化 pass 数：${passResults.length}`,
    `- 判定为「违规」的 pass 数：${violationCount}`,
    `- 判定为「疑似违规」的 pass 数：${suspectCount}`,
    "",
    "## 各优化 Pass 分析",
    "",
    passSections || "- 未识别到优化 pass。",
    "",
    "## 汇总结论",
    "",
    synthesisMarkdown,
    "",
    "## 说明",
    "",
    "- 本报告由 DeepSeek 分阶段通读仓库全部代码、逐 pass 分析生成：先定位优化 pass，再逐个读取其完整源码判断原理与合规性，最后汇总。",
    "- 摘要值使用 HMAC-SHA256（密钥由服务端保管）对报告全文计算，可在管理员验证界面校验报告是否被篡改。",
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
    const collectResult = await collectRepository(repoDir);

    // Map：依据文件清单识别优化 pass
    const manifest = buildFileManifest(collectResult.files);
    const mapPrompt = buildMapPrompt({ repoUrl: sanitizedRepoUrl, branch, manifest });
    const mapResult = await callDeepSeekJson({ apiKey, prompt: mapPrompt });
    const passes = Array.isArray(mapResult?.passes) ? mapResult.passes : [];

    // Reduce：读取所有 pass 源码，按 token 预算分批，每批一次调用分析多个 pass
    const passItems = [];
    for (const pass of passes) {
      const sources = await readPassSources(pass, collectResult.files);
      passItems.push({ pass, sources });
    }

    const batchBudget = Math.max(8000, DEEPSEEK_MAX_INPUT_TOKENS - 8000);
    const batches = packPassesIntoBatches(passItems, batchBudget);
    const passResults = [];
    for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
      const batch = batches[batchIndex];
      try {
        const passPrompt = buildPassBatchPrompt({
          batch,
          rulesMarkdown,
          batchIndex,
          batchCount: batches.length,
        });
        const result = await callDeepSeekJson({ apiKey, prompt: passPrompt });
        const array = Array.isArray(result) ? result : [];
        for (let i = 0; i < batch.length; i += 1) {
          const item = array[i];
          if (item) {
            passResults.push(item);
          } else {
            passResults.push({
              passName: batch[i].pass.name ?? "未知",
              error: "该批分析未返回对应结果",
            });
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "分析失败";
        for (const item of batch) {
          passResults.push({ passName: item.pass.name ?? "未知", error: message });
        }
      }
    }

    // Synthesize：汇总各 pass 结论
    let synthesisMarkdown;
    if (passes.length === 0) {
      synthesisMarkdown = "未能从仓库中识别出优化 pass，无法进行逐 pass 分析。建议人工检查仓库结构。";
    } else {
      try {
        const synthesisPrompt = buildSynthesisPrompt({
          repoUrl: sanitizedRepoUrl,
          branch,
          passResults,
          rulesMarkdown,
        });
        synthesisMarkdown = await callDeepSeek({ apiKey, prompt: synthesisPrompt });
      } catch (error) {
        synthesisMarkdown = `汇总失败：${error instanceof Error ? error.message : "未知错误"}`;
      }
    }

    const reportMarkdown = buildFinalReport({
      repoUrl: sanitizedRepoUrl,
      branch,
      auditId,
      rulesPath: RULES_PATH,
      collectResult,
      passResults,
      synthesisMarkdown,
    });

    const reportHashHex = hmacDigestHex(reportMarkdown);

    await writeAuditArtifacts({
      auditId,
      reportMarkdown,
      reportHashHex,
      metadata: {
        auditId,
        repoUrl: sanitizedRepoUrl,
        branch,
        generatedAt: new Date().toISOString(),
        passCount: passResults.length,
        verdicts: {
          违规: passResults.filter((passResult) => passResult.verdict === "违规").length,
          疑似违规: passResults.filter((passResult) => passResult.verdict === "疑似违规").length,
          合规: passResults.filter((passResult) => passResult.verdict === "合规").length,
        },
        digestAlgorithm: "HMAC-SHA256",
      },
    });

    json(response, 200, {
      auditId,
      repoUrl: sanitizedRepoUrl,
      branch,
      reportMarkdown,
      reportHashHex,
      digestAlgorithm: "HMAC-SHA256",
      passCount: passResults.length,
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

async function handleAdminLogin(request, response) {
  const body = await parseJsonBody(request);
  const password = String(body.password ?? "");
  const db = await readDb();
  const admin = db?.admin;

  if (!admin || !verifyPassword(password, admin.salt, admin.passwordHash)) {
    json(response, 401, { error: "密码错误" });
    return;
  }

  json(response, 200, {
    token: signAdminToken(),
    expiresInMs: ADMIN_TOKEN_TTL_MS,
    mustChangePassword: admin.mustChangePassword === true,
  });
}

async function handleAdminChangePassword(request, response) {
  if (!verifyAdminToken(readBearerToken(request))) {
    json(response, 401, { error: "未登录或登录已过期，请重新登录" });
    return;
  }

  const body = await parseJsonBody(request);
  const currentPassword = String(body.currentPassword ?? "");
  const newPassword = String(body.newPassword ?? "");

  if (newPassword.length < 6) {
    json(response, 400, { error: "新密码长度至少 6 位" });
    return;
  }

  const db = await readDb();
  const admin = db?.admin;
  if (!admin || !verifyPassword(currentPassword, admin.salt, admin.passwordHash)) {
    json(response, 401, { error: "当前密码错误" });
    return;
  }

  const { salt, hash } = hashPassword(newPassword);
  admin.salt = salt;
  admin.passwordHash = hash;
  admin.mustChangePassword = false;
  admin.updatedAt = new Date().toISOString();
  await writeDb(db);

  json(response, 200, { ok: true, message: "密码已更新" });
}

async function handleAdminVerify(request, response) {
  if (!verifyAdminToken(readBearerToken(request))) {
    json(response, 401, { error: "未登录或登录已过期，请重新登录" });
    return;
  }

  const db = await readDb();
  if (db?.admin?.mustChangePassword) {
    json(response, 403, { error: "请先修改初始密码后再进行验证" });
    return;
  }

  const body = await parseJsonBody(request);
  const digest = String(body.digest ?? "").trim().toLowerCase();
  const contentBase64 = String(body.contentBase64 ?? "");
  const fileName = String(body.fileName ?? "").trim();

  if (!/^[a-f0-9]{64}$/.test(digest)) {
    json(response, 400, { error: "摘要值格式不正确，应为 64 位十六进制字符串" });
    return;
  }

  if (!contentBase64) {
    json(response, 400, { error: "请先上传需要验证的文件" });
    return;
  }

  let content;
  try {
    content = Buffer.from(contentBase64, "base64");
  } catch {
    json(response, 400, { error: "文件内容解析失败" });
    return;
  }

  if (content.length === 0 || content.length > 5 * 1024 * 1024) {
    json(response, 400, { error: "文件为空或超过 5MB 限制" });
    return;
  }

  const computedDigest = hmacDigestHex(content);
  const consistent = safeEqual(computedDigest, digest);

  json(response, 200, {
    fileName,
    consistent,
    message: consistent ? "一致" : "不一致",
    computedDigest,
    providedDigest: digest,
    digestAlgorithm: "HMAC-SHA256",
  });
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

    if (request.method === "POST" && requestUrl.pathname === "/api/admin/login") {
      await handleAdminLogin(request, response);
      return;
    }

    if (request.method === "POST" && requestUrl.pathname === "/api/admin/change-password") {
      await handleAdminChangePassword(request, response);
      return;
    }

    if (request.method === "POST" && requestUrl.pathname === "/api/admin/verify") {
      await handleAdminVerify(request, response);
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

if (!HMAC_SECRET) {
  console.error("缺少 HMAC_SECRET，请在 .env 中配置用于防篡改摘要和登录令牌的密钥。");
  process.exit(1);
}

await fsp.mkdir(REPORTS_DIR, { recursive: true });
await fsp.mkdir(WORKSPACE_DIR, { recursive: true });
await fsp.mkdir(path.dirname(DB_PATH), { recursive: true });

const adminInit = await ensureAdminInitialized();
if (adminInit.created) {
  console.warn("【注意】管理员初始密码为 admin123，首次登录后将强制要求修改。");
}

server.listen(PORT, HOST, () => {
  console.log(`GitLab 违规审核工具已启动：http://${HOST}:${PORT}`);
});
