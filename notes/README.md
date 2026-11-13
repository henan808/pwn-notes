# 笔记投递区

**往这里丢 `.md` 文件就行**，不用写 Hexo 的 front matter、不用管图片路径、不用手动建文章。

```bash
# 方式一：只同步，看看会生成什么
npm run sync -- --dry

# 方式二：同步 + 提交（本地）
npm run publish

# 方式三：同步 + 提交 + 推送，博客几分钟后自动更新（需先配好 git 凭据）
npm run publish -- --push

# 方式四：后台挂着，笔记一保存就自动发布
npm run watch
```

## 一个文件 = 一篇文章

`notes/tcache-stash.md` → 自动生成 `source/_posts/sync-notes-tcache-stash-xxxxxx.md`。
文件名当标题；想换标题就在文件开头写 front matter：

```markdown
---
title: tcache stash 机制详解
categories: [知识点, 堆]
tags: [tcache, glibc2.27, stash]
---
正文……
```

不写也没关系：脚本会从标题和正文**自动猜分类和标签**（堆 / 栈 / 格式化字符串 / 题目复现+赛事，以及 libc 版本、unlink、fastbin 等手法标签）。

## 大文件可以自动拆

在 `notes-sources.json` 里把某个源的 `mode` 设成 `split-h1`，脚本按 `# 一级标题` 拆成多篇。
**代码块里的 `# 注释` 会被自动跳过**（你的 `pwn题目.md` 里有大量 `# ===== Step 1 =====` 这种 Python 注释）。
太短的章节（默认 < 160 字符）自动丢弃。

## 图片自动搬运

Typora 的绝对路径可以直接用：

```markdown
![bins](C:\Users\86139\AppData\Roaming\Typora\typora-user-images\image-xxx.png)
```

同步时会把图片复制到 `source/_posts/<slug>/`，并改写成 `![](image-xxx.png)` —— 只写文件名。
（`hexo-renderer-marked` 的 `postAsset` 会自己拼文章资源目录，写成 `./<slug>/image.png` 反而会 404。）
相对路径的图片按笔记所在目录解析；找不到的图片会保留原链接并在报告里列出来，不会静默丢掉。

## 幂等与安全

- 每篇生成文章里有一个 `<!-- sync-hash: ... -->`。**源笔记没变就不重写**，重复跑不会产生 git 噪声；重写时会保留原来的 `date`，文章不会突然跳到最前面。
- 只管理 `source/_posts/sync-*.md`。你手写的文章、之前导入的 `imported-*.md` **一律不动**。
- 生成文件请勿手改；要改就改 `notes/` 里的源笔记，再同步一次。
- 外部笔记（`D:\笔记\` 等）**只读**，脚本不会修改、移动或删除你的原文件。
- 源章节删掉后，对应的生成文章默认保留（怕误删）。确认无误可跑 `npm run sync -- --prune` 清理。

## 公开仓库提醒

`notes/` 里的原稿会一起 push 到公开仓库。涉及未公开赛事的 flag、靶机内网地址、个人邮箱、草稿吐槽，发布前自己过一遍。
外部大笔记默认是**关闭**的，要在 `notes-sources.json` 里把 `enabled` 改成 `true` 才会同步。
