# GitLab 仓库违规审核工具

这是一个独立的前后端小工具，用于：

1. 在前端输入 GitLab 仓库链接和分支名
2. 后端拉取对应仓库
3. 读取 `违规说明.md`
4. 结合程序化扫描结果，调用 DeepSeek API 对仓库进行违规审核
5. 生成 Markdown 审核报告
6. 对报告生成摘要值，并在前端展示和下载

## 项目目录

```text
gitlab-violation-auditor/
├── public/          # 前端静态页面
├── reports/         # 生成后的审核报告和摘要文件
├── workspace/       # 临时克隆仓库目录，审核结束后会清理
├── data/            # 管理员密码数据库（db.json，scrypt 加盐哈希存储）
├── package.json
├── server.js
└── README.md
```

## 运行要求

- Node.js >= 20
- git
- 可访问 DeepSeek API

## 环境变量

项目启动时会自动读取根目录下的 `.env` 文件，因此**需要用户自行创建** `.env`。

可以参考下面的内容：

```bash
DEEPSEEK_API_KEY=your_deepseek_api_key
PORT=3000
HOST=0.0.0.0
DEEPSEEK_BASE_URL=https://api.deepseek.com
HMAC_SECRET=please_generate_a_random_secret
```

其中：

- `DEEPSEEK_API_KEY`：必填，你自己的 DeepSeek API Key
- `PORT`：可选，服务监听端口，默认 `3000`
- `HOST`：可选，服务监听地址，默认 `0.0.0.0`
- `DEEPSEEK_BASE_URL`：可选，默认 `https://api.deepseek.com`
- `HMAC_SECRET`：必填，用于计算报告防篡改摘要和签名登录令牌的密钥（请自行生成随机字符串）

## 启动方式

```bash
npm start
```

如果你还没有创建 `.env`，可以先执行：

```bash
cat > .env <<'EOF'
DEEPSEEK_API_KEY=your_deepseek_api_key
PORT=3000
HOST=0.0.0.0
DEEPSEEK_BASE_URL=https://api.deepseek.com
HMAC_SECRET=please_generate_a_random_secret
EOF
```

启动后访问：

```text
http://127.0.0.1:3000
```

## 使用说明

1. 输入 GitLab 仓库链接
2. 输入分支名
3. 如果仓库是私有仓库，可填写 GitLab Personal Access Token
4. 点击“开始审核”
5. 等待后端拉取仓库、扫描代码、调用 DeepSeek 生成 Markdown 报告
6. 在前端查看：
   - 审核报告 Markdown 预览
   - 报告摘要值
   - Markdown 报告下载链接
   - 摘要文件下载链接

## 页面与权限

系统分为三个页面：

- **报告生成**（`/`）：任何人都可以操作，无需登录。
- **验证报告**（`/verify.html`）：仅管理员可操作，进入时会先弹出登录框要求输入密码。
- **修改密码**（`/password.html`）：仅管理员可操作，进入时会先弹出登录框要求输入密码。

管理员初始密码为 `admin123`，**首次登录后会被强制要求修改密码**；密码不以明文出现在 `.env` 中，而是以 `scrypt` 加盐哈希保存在 `data/db.json`。

## 管理员验证与防篡改

报告摘要使用 **HMAC-SHA256**（带密钥的消息认证码）计算，密钥保存在服务端（`.env` 的 `HMAC_SECRET`），因此只有持有该密钥才能重新算出有效摘要，能做到真正的「防篡改」（普通 SHA-256 无法防止被替换重算）。

在「验证报告」页面中：

1. 上传原始文件（例如下载的 `analysis.md`）
2. 输入文件处理后的摘要值（例如 `hash.txt` 中的十六进制字符串）
3. 点击「开始验证」，系统会重新计算 HMAC-SHA256 摘要并比对：
   - 一致 → 文件未被篡改
   - 不一致 → 文件已被篡改

## 当前实现说明

- 为了避免把整个大仓库一股脑发给模型，后端会先做一层程序化扫描：
  - 搜索特定样例名/测试点标识
  - 搜索函数名匹配/字符串匹配痕迹
  - 搜索输入模式判断痕迹
  - 搜索部分硬编码常量
- 然后把：
  - `违规说明.md`
  - 仓库文件摘要
  - 程序化线索
  - 若干重点文件内容
    一起交给 DeepSeek 生成更完整的审核报告。

## 输出文件

每次审核都会在 `reports/<auditId>/` 下生成：

- `analysis.md`：审核报告
- `hash.txt`：报告摘要值（HMAC-SHA256 十六进制）
- `metadata.json`：基础元信息

## 注意事项

- 当前版本优先支持 `http/https` 的 GitLab 仓库地址。
- 私有仓库建议通过前端填写 GitLab Token。
- 审核报告属于“程序化扫描 + 大模型分析”的组合结论，适合作为初审材料；最终是否违规仍建议人工复核。
