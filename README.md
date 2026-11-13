# Pwn Notes · Hexo 个人笔记站

用来记 **Pwn 知识点**和 **CTF 题目复现** 的静态博客。Hexo 7 + Fluid 主题，Markdown 写文章，push 到 GitHub 后由 Actions 自动构建并发布到 GitHub Pages。

站点结构、分类约定、写作模板见博客里的第一篇文章《从这里开始：怎么写这个站的笔记》（`source/_posts/start-here.md`）。

## 目录结构

```
hexo-pwn-notes/
├── _config.yml                 # Hexo 主配置（站点信息 / 目录 / 高亮 / 搜索）
├── _config.fluid.yml           # Fluid 主题覆盖配置
├── notes/                      # ★ 笔记投递区：往这里丢 .md 就行
│   ├── README.md               # 投递区写法说明
│   └── external/               # 外部笔记的只读副本（含 assets/ 图片）
├── notes-sources.json          # ★ 笔记源配置：外部路径 / 大文件拆分 / 默认分类
├── package.json                # 依赖与快捷命令
├── scaffolds/                  # post / knowledge / writeup / tool 四种文章模板
├── tools/
│   ├── sync_notes.py           # ★ 笔记 -> 文章（front matter / 分类 / 图片 / 幂等）
│   ├── publish.py              # ★ 一键：同步 + 提交 + 可选推送
│   ├── watch_notes.py          # ★ 后台监听，笔记一保存就自动发布
│   ├── new_post.py             # 传统方式：新建带模板的文章
│   └── import_from_wp.py       # 把已有题解批量导进来
├── source/
│   ├── _posts/*.md             # 生成的 sync-*.md + 手写文章
│   ├── about/index.md          # 关于页
│   └── .nojekyll               # 跳过 GitHub Pages 的 Jekyll 处理
└── .github/workflows/deploy.yml  # push 自动同步笔记 + 构建 + 部署
```

## 快速开始

```bash
cd hexo-pwn-notes
npm install              # 首次；已装好则可跳过
npm run server           # 本地预览 http://127.0.0.1:4000/pwn-notes/
npm run build            # 生成 public/
```

## 写笔记（推荐：只管写，发布交给脚本）

**把 `.md` 丢进 `notes/` 就够了**，不用写 front matter、不用管图片路径：

```bash
# 看看会生成什么（不写文件）
npm run sync:dry

# 同步 + 自动 git commit
npm run publish

# 同步 + 提交 + 推送；Actions 1–2 分钟后博客自动更新
npm run publish -- --push

# 后台挂着：笔记一保存（静默 8 秒）就自动同步、提交、推送
npm run watch
```

`notes-sources.json` 里可以配外部笔记源。例如把 `D:\笔记\pwn题目.md` 的 `enabled` 改成 `true`，
它会按 `# 一级标题` 自动拆成多篇（**代码块里的 `# 注释` 会跳过**），图片自动搬进
`notes/external/<name>/assets/`，让仓库自包含、CI 也能复现。外部原文件**只读**，不会被改动。

同步器会做这些事：

| 能力 | 说明 |
|---|---|
| 自动 front matter | 标题取正文第一个 `# 标题`（并从正文移除，避免重复）；分类/标签按 Pwn 关键词推断 |
| 图片搬运 | Typora 绝对路径 `C:\...\typora-user-images\x.png` → 复制到文章资源目录并改成相对路径 |
| 幂等 | 文末写 `sync-hash`，源没变就跳过；重写时保留原 `date`，不会把旧文章顶到最前 |
| 不误伤 | 只管理 `source/_posts/sync-*.md`，手写文章和 `imported-*.md` 一律不动 |
| 清理 | 源章节删掉后跑 `npm run sync -- --prune` 才删对应文章，默认保留防误删 |

> 生成文件请勿手改，改 `notes/` 里的源笔记再同步一次即可。详细说明见 `notes/README.md`。

**传统方式**仍然可用（想直接用 Hexo 模板写时）：

```bash
python tools/new_post.py --title "tcache stash 机制" --type knowledge \
  --sub 堆 --tags tcache,glibc2.27 --slug tcache-stash
python tools/new_post.py --title "[BUUCTF] xxx" --type writeup \
  --sub BUUCTF --tags unlink,libc2.23 --slug buuctf-xxx
python tools/import_from_wp.py --dry     # 导入工作区已有题解
python tools/import_from_wp.py
```

`post_asset_folder: true`，每篇文章带同名图片目录，gdb 截图放进去后**只写文件名**引用：`![](bins.png)`（`postAsset` 会自动补文章路径）。
分类约定：`知识点 / 题目复现 / 工具与环境 / 指南`，二级为方向或赛事；标签用 `glibc2.27`、`tcache`、`unlink`、`HouseOfSpirit` 这类便于检索的词。

## 部署到 GitHub Pages

`_config.yml` / `_config.fluid.yml` 里的占位符**已经按 GitHub 用户名 `henan808` 填好**：

| 字段 | 当前值 |
|---|---|
| `url` | `https://henan808.github.io/pwn-notes`（**项目页要带子路径**） |
| `root` | `/pwn-notes/`（对应项目仓库名 `pwn-notes`） |
| `author` | `henan808` |
| `about.icons` | 指向 `https://github.com/henan808` 和本站源码仓库 |

> `url` 为什么要带 `/pwn-notes`：Hexo 的 `full_url_for`（用于 `og:url`、文章版权里的永久链接）是 `url + 页面路径`，**不会拼 `root`**；只有菜单、CSS 这类相对链接才走 `root`。少写子路径会让分享链接指到站点根。
>
> 若你改把仓库命名为 `henan808.github.io`（用户主页站点），把 `url` 改成 `https://henan808.github.io`、`root` 改成 `/`。

**不需要在仓库里放任何密码或 token。** 剩下三步：

1. 在 GitHub 上新建名为 **`pwn-notes`** 的空仓库（不要勾选初始化 README / LICENSE，避免冲突）。

2. 推送（`git init`、首次提交 `4df4030`、分支 `main`、`origin` 远端都已在本地配好）：

   ```bash
   git push -u origin main
   ```

   命令行认证时，GitHub 要的是 **PAT（勾选 `repo`）当密码**，不是账号密码；也可以改用 SSH：`git@github.com:henan808/pwn-notes.git`。
   以后日常更新直接用 `npm run publish -- --push`，或挂着 `npm run watch` 全自动。

3. 仓库网页上设置：
   - **Settings → Actions → General → Workflow permissions** → 勾 `Read and write permissions`（让 Actions 能推 `gh-pages`）。
   - **Settings → Pages → Build and deployment** → Source 选 `Deploy from a branch`，分支 `gh-pages`、目录 `/root`。
   - 之后每次 `git push`，`.github/workflows/deploy.yml` 会自动 `npm ci → hexo generate → 部署`，约 1–2 分钟后生效。

部署用的是 GitHub 自动注入的 `secrets.GITHUB_TOKEN`，**不需要你配置 PAT**。若你想本地手动 `hexo deploy`，再在 `_config.yml` 里放开 `deploy` 段并填 SSH 地址。

## 凭据安全（务必看）

- **不要把 GitHub 账号密码、Personal Access Token、SSH 私钥写进这个仓库的任何文件**，也不要写进 commit message、workflow 或 `_config.yml`。`.gitignore` 已排除 `.env`、`*token*`、`_config.local.yml`、`credentials*` 等。
- GitHub 自 2021 年 8 月起**不再接受账号密码推送代码**。命令行推送要用 **PAT（勾选 `repo` 权限）作为密码**，或改用 SSH key；用上面的 Actions 方案则完全不必碰这些。
- 如果曾经在聊天、截图或别处暴露过密码：**立刻去 GitHub 改密码并开启两步验证**，旧密码视为已泄露。
- 本站是公开仓库，题解里的靶机 IP、内网地址、个人邮箱按需脱敏；不要提交尚未公开赛事的 flag 或攻击性脚本针对真实目标的部分。

## 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 本地预览 404 | `root: /pwn-notes/`，预览地址必须是 `http://127.0.0.1:4000/pwn-notes/`，不是 `/` |
| `npm run server` 报 `Unknown command server` | Hexo 7 把本地服务器拆成独立包 `hexo-server`，已在 `package.json` 声明，执行 `npm install` 即可 |
| Actions 报 `npm ci` 失败 | 把 `package-lock.json` 一起提交（已在仓库里） |
| Actions 部署 403 | 没开 `Read and write permissions` |
| 分类页 / 标签页空白 | 确认 `hexo-generator-category` / `hexo-generator-tag` 已安装，且文章 front matter 里写了 `categories` / `tags` |
| 搜索没结果 | 主配置 `search.path` 与 `_config.fluid.yml` 的 `search.path` 都要是 `/local-search.xml` |
| 生成的 HTML 里出现 `<% ... %>` 源码 | 缺 `hexo-renderer-ejs` / `hexo-renderer-stylus`（Fluid 的 layout 是 `.ejs`、样式是 `.styl`）。执行 `npm install` 补齐，两者已在 `package.json` 显式声明 |
| 代码块没有高亮 | `_config.yml` 的 `highlight.enable: true` 由 Hexo 服务端生成 `<figure class="highlight">`；若改成 `false` 才依赖主题的 highlightjs CDN |
| mermaid 图不渲染 | 文章里用 ` ```mermaid ` 代码块；`post.mermaid.enable` 已开，依赖 `hexo-filter-mermaid-diagrams` |
| 图片不显示 | 手写文章把截图放进同名资源目录，引用只写文件名 `![](<file>.png)`；写成 `./<slug>/<file>.png` 会 404。`notes/` 源笔记的绝对路径图片由 `sync_notes.py` 自动搬运 |
| `push` 报认证失败 | GitHub 不接受账号密码，需 PAT（`repo` 权限）或 SSH key；脚本不保存任何凭据，认证交给系统 git |
| 大笔记拆出一堆奇怪章节 | 确认 `mode: split-h1`；代码块里的 `# 注释` 会被跳过，太短章节由 `min_chars` 过滤 |
| 改了 `sync-*.md` 又被覆盖 | 这些是自动生成文件，请改 `notes/` 里的源笔记后重新 `npm run sync` |
| 忘了本地同步直接 push | 不会漏：Actions 在构建前有 `python3 tools/sync_notes.py --ci`，会用仓库里的 `notes/` 重新生成 |
| 外部笔记没同步 | 检查 `notes-sources.json` 里该源的 `enabled` 是否为 `true`、路径是否存在；同步是只读的，不会改原文件 |
| 源章节删了但文章还在 | 默认保留防误删，确认后跑 `npm run sync -- --prune` |

## 已有内容（6 篇）

手写示例：

- 《从这里开始：怎么写这个站的笔记》— 使用说明
- 《glibc 堆基础：chunk 结构、request2size 与 bins》— 知识点示例
- 《ciscn_2019_final_3：四种流派怎么泄露 libc》— 题目复现示例

由 `tools/import_from_wp.py` 从工作区 `WP/实战记录/Pwn/` 导入：

- `imported-ciscn_2019_final_3.md` — CISCN 2019 决赛堆题，五流派完整题解
- `imported-fmt_cache.md` — 格式化字符串改 check + FILE IO 缓存读 flag
- `imported-roarctf2019_easyheap.md` — libc 2.23 unlink + fastbin attack

以后新增题解，跑 `npm run import` 即可增量导入（`--dry` 先预览，`--force` 覆盖重导）。
