---
title: 从这里开始：怎么写这个站的笔记
date: 2026-11-13 17:40:00
categories:
  - 指南
tags:
  - Hexo
  - 写作规范
---

这个站跑在 Hexo + Fluid 上，源文章就是 `source/_posts/*.md` 里的纯 Markdown。**本地只写 Markdown，push 到 GitHub 后 Actions 自动构建并发布到 GitHub Pages**，不需要在本地跑 `hexo deploy`。

## 三类内容与分类约定

| 类型 | 一级分类 | 二级分类示例 | scaffold |
|---|---|---|---|
| 知识点 | `知识点` | `堆` `栈` `格式化字符串` `ROP` `内核` `保护机制` | `knowledge` |
| 题目复现 | `题目复现` | `BUUCTF` `CISCN` `RoarCTF` `其他赛事` | `writeup` |
| 工具环境 | `工具与环境` | `libc切换` `pwndbg` `Docker` | `post` |
| 站点说明 | `指南` | — | `post` |

分类用 Hexo 的层级写法，第二个元素会成为子分类：

```yaml
categories:
  - 知识点
  - 堆
tags: [glibc2.27, tcache, UAF]
```

标签建议统一用小写/驼峰，方便归档：`glibc2.23`、`glibc2.27`、`tcache`、`unlink`、`HouseOfSpirit`、`fastbin`、`fmtstr`、`one_gadget`、`FullRELRO`。

## 最省事的写法：丢进 `notes/` 就自动发布

平时的笔记不用管 Hexo 格式，**直接把 `.md` 放进仓库的 `notes/` 目录**：

```bash
npm run sync:dry              # 预览会生成哪些文章
npm run publish -- --push     # 同步 + 提交 + 推送，Actions 自动上线
npm run watch                 # 或者挂着，笔记一保存就全自动
```

同步器会补好 front matter（标题取正文第一个 `# 标题`、按关键词推断分类和标签）、
把 Typora 的绝对路径截图搬进文章资源目录并改成相对路径、
用 `sync-hash` 保证源没变就不重写。大笔记可以在 `notes-sources.json` 里配 `split-h1`，
按一级标题拆成多篇，**代码块里的 `# 注释` 不会被误判成标题**。
外部笔记（`D:\笔记\` 等）只读同步，原文件不会被改动。完整规则见 `notes/README.md`。

> 生成的是 `source/_posts/sync-*.md`，请勿手改；要改就改 `notes/` 里的源笔记再同步一次。
> 就算本地忘了同步，Actions 在构建前也会跑一次 `python3 tools/sync_notes.py --ci` 兜底。

下面的 `new_post.py` / `import_from_wp.py` 是传统方式，想直接按模板写或批量导入旧题解时仍然可用。

## 新建一篇

```bash
python tools/new_post.py --title "tcache stash 机制" --type knowledge \
  --sub 堆 --tags tcache,glibc2.27 --slug tcache-stash

python tools/new_post.py --title "[RoarCTF 2019] easyheap" --type writeup \
  --sub RoarCTF --tags unlink,libc2.23,HouseOfSpirit --slug roarctf2019-easyheap
```

脚本会生成带好 front matter 的 `.md`，并在同目录建一个同名资源文件夹（因为 `post_asset_folder: true`）—— **gdb 截图、bins dump、堆布局图直接丢进去**，文章里用相对路径引用：

```markdown
![add(8) 之后的 bins](./tcache-stash/bins-after-add8.png)
```

## 把已有题解批量导进来

工作区里已有的 `WP/实战记录/Pwn/*.md` 可以一键转成 Hexo 文章：

```bash
python tools/import_from_wp.py --dry      # 先看会生成什么
python tools/import_from_wp.py            # 实际写入 source/_posts/imported-*.md
```

脚本会读原文件的 YAML front matter（题名 / 赛事 / 技术栈 / 日期），转成 `title`、`date`、`categories: [题目复现, <赛事>]`、`tags`，并把原来的元信息保留成正文顶部的引用块，正文一字不改。

## 本地预览与构建

```bash
npm install
npm run server          # http://127.0.0.1:4000/pwn-notes/
npm run build           # 生成到 public/
```

## 部署

默认走 `.github/workflows/deploy.yml`：`push` 到 `main` → `npm ci` → `hexo generate` → 推到 `gh-pages` 分支。**只需要 GitHub 自带的 `GITHUB_TOKEN`，不需要你配置任何密码或 token。**

本站已按 GitHub 用户名 `henan808` 配好 `_config.yml`（`url: https://henan808.github.io/pwn-notes`、`root: /pwn-notes/`、`author: henan808`）和 `_config.fluid.yml` 的主页链接，首次使用只需三步：

1. 在 GitHub 建一个名为 **`pwn-notes`** 的空仓库，把本目录 `git push -u origin main` 推上去（认证用 PAT 或 SSH key，不用账号密码）。
2. 仓库 Settings → Pages → Build and deployment → Source 选 `Deploy from a branch`，分支选 `gh-pages` / `root`。
3. 仓库 Settings → Actions → General → Workflow permissions 勾 `Read and write permissions`。

> 如果想用 `henan808.github.io` 作为用户主页站点，把仓库改成同名，并把 `_config.yml` 的 `url` 改成 `https://henan808.github.io`、`root` 改成 `/`。`url` 必须带项目子路径，是因为 Hexo 的 `full_url_for` 只用 `url + 页面路径`，不会拼 `root`。

## 安全提醒

- **绝对不要把 GitHub 密码、PAT、SSH 私钥写进这个仓库的任何文件、commit message 或 workflow。** `.gitignore` 已经排除了 `.env`、`*token*`、`_config.local.yml` 等。
- GitHub 自 2021 年 8 月起**不再接受账号密码推送代码**，需要 PAT（勾选 `repo`）或 SSH key；用 Actions 方案则完全不用碰这些。
- 本站公开，题解里的靶机地址、内网 IP、个人邮箱按需脱敏。
