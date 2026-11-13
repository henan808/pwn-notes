#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键发布：同步笔记 -> （可选）本地构建验证 -> git commit -> （可选）push。

push 成功后，GitHub Actions 会自动 build + 部署到 gh-pages，博客就更新了。
脚本不读取、不保存、不生成任何凭据；git 认证完全交给系统已有的凭据/PAT/SSH key。

用法：
  npm run publish                     # 同步 + 提交
  npm run publish -- --push           # 同步 + 提交 + 推送（真正上线）
  npm run publish -- --dry            # 只预览，不动文件也不提交
  npm run publish -- --prune --push   # 顺带清理源已删掉的旧文章
  npm run publish -- --build          # 提交前先本地 hexo generate 验证
  npm run publish -- --no-commit      # 只同步，不碰 git
"""
import argparse
import datetime
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import sync_notes  # noqa: E402


def git(args, check=True, capture=True):
    cmd = ['git'] + args
    r = subprocess.run(cmd, cwd=ROOT, capture_output=capture, text=True,
                       encoding='utf-8', errors='replace')
    if check and r.returncode != 0:
        raise RuntimeError('git %s 失败：%s' % (' '.join(args), (r.stderr or '').strip()))
    return r


def in_repo():
    return git(['rev-parse', '--is-inside-work-tree'], check=False).returncode == 0


def main():
    ap = argparse.ArgumentParser(description='同步笔记并提交/推送')
    ap.add_argument('--push', action='store_true', help='推送到远端（触发 Actions 部署）')
    ap.add_argument('--dry', action='store_true', help='只预览同步结果，不写文件、不提交')
    ap.add_argument('--prune', action='store_true', help='清理源已消失的生成文章')
    ap.add_argument('--force', action='store_true', help='忽略 hash，全部重新生成')
    ap.add_argument('--build', action='store_true', help='提交前本地构建验证（默认关，CI 会构建）')
    ap.add_argument('--no-commit', action='store_true', help='只同步，不执行任何 git 操作')
    ap.add_argument('--message', default='', help='自定义 commit message')
    args = ap.parse_args()

    # 1) 同步
    print('[1/4] 同步笔记 -> Hexo 文章')
    try:
        report = sync_notes.run(stage=True, dry=args.dry, force=args.force,
                                prune=args.prune, quiet=True)
    except Exception as e:
        print('同步失败：%s: %s' % (type(e).__name__, e), file=sys.stderr)
        return 1
    sync_notes.print_report(report)
    if args.dry:
        print('\n[dry] 未写文件、未提交、未推送。去掉 --dry 才会真正执行。')
        return 0
    if args.no_commit:
        print('\n[--no-commit] 已完成同步，未执行 git 操作。')
        return 0

    # 2) 可选构建验证
    if args.build:
        print('\n[2/4] 本地构建验证')
        npx = 'npx.cmd' if os.name == 'nt' else 'npx'
        r = subprocess.run([npx, 'hexo', 'generate'], cwd=ROOT,
                           capture_output=True, text=True, encoding='utf-8', errors='replace')
        if r.returncode != 0:
            print('构建失败，已中止发布（不提交）：\n' + (r.stderr or r.stdout or '')[-1500:],
                  file=sys.stderr)
            return 1
        print('构建通过。')
    else:
        print('\n[2/4] 跳过本地构建（CI 会构建；加 --build 可本地验证）')

    # 3) 提交
    if not in_repo():
        print('当前目录不是 git 仓库，跳过提交。', file=sys.stderr)
        return 1
    print('\n[3/4] 暂存并提交')
    git(['add', '-A'])
    diff = git(['diff', '--cached', '--quiet'], check=False)
    if diff.returncode == 0:
        print('没有需要提交的改动。')
    else:
        staged = git(['diff', '--cached', '--name-only'], check=False).stdout.strip()
        print('将提交：\n  ' + '\n  '.join(staged.splitlines()[:20]))
        if len(staged.splitlines()) > 20:
            print('  ... 共 %d 个文件' % len(staged.splitlines()))
        msg = args.message or ('notes: auto sync %s (%d new/updated)'
                               % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
                                  report['written']))
        git(['commit', '-m', msg])
        print('已提交：' + msg)

    # 4) 推送
    if not args.push:
        print('\n[4/4] 未推送。要上线请加 --push（或先手动 git push）。')
        return 0
    print('\n[4/4] 推送到远端')
    remotes = git(['remote'], check=False).stdout.split()
    if 'origin' not in remotes:
        print('没有 origin 远端。先执行：git remote add origin <仓库地址>', file=sys.stderr)
        return 1
    branch = git(['branch', '--show-current'], check=False).stdout.strip() or 'main'
    r = git(['push', 'origin', 'HEAD:' + branch], check=False)
    if r.returncode != 0:
        print('推送失败：\n' + (r.stderr or r.stdout or '').strip()[-1200:], file=sys.stderr)
        print('\n提示：GitHub 自 2021 年起不接受账号密码推送，需要 PAT（勾选 repo）或 SSH key；'
              '\n      也可以先在网页上建好名为 pwn-notes 的空仓库。'
              '\n      本地提交已经生成，配好凭据后执行 git push origin %s 即可。' % branch,
              file=sys.stderr)
        return 1
    print('推送完成，GitHub Actions 将在 1-2 分钟后更新博客。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
