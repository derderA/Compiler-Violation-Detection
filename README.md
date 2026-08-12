# GitLab 仓库违规审核工具

这是一个独立的前后端小工具，用于：

1. 在前端输入 GitLab 仓库链接和分支名
2. 后端拉取对应仓库
3. 读取 `/home/derder/update_compiler/违规说明.md`
4. 结合程序化扫描结果，调用 DeepSeek API 对仓库进行违规审核
5. 生成 Markdown 审核报告
6. 对报告生成摘要值，并在前端展示和下载

## 项目目录

```text
gitlab-violation-auditor/
├── public/          # 前端静态页面
├── reports/         # 生成后的审核报告和摘要文件
├── workspace/       # 临时克隆仓库目录，审核结束后会清理
├── package.json
├── server.js
└── README.md
```

## 运行要求

- Node.js >= 20
- git
- 可访问 DeepSeek API

## 环境变量

至少需要配置：

```bash
export DEEPSEEK_API_KEY="你的 deepseek key"
```

可选：

```bash
export PORT=3000
export HOST=0.0.0.0
export DEEPSEEK_BASE_URL="https://api.deepseek.com"
```

## 启动方式

```bash
cd /home/derder/gitlab-violation-auditor
node server.js
```

或者：

```bash
cd /home/derder/gitlab-violation-auditor
npm start
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
- `hash.txt`：报告摘要值（十六进制）
- `metadata.json`：基础元信息

## 注意事项

- 当前版本优先支持 `http/https` 的 GitLab 仓库地址。
- 私有仓库建议通过前端填写 GitLab Token。
- 审核报告属于“程序化扫描 + 大模型分析”的组合结论，适合作为初审材料；最终是否违规仍建议人工复核。
