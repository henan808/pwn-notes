#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""后台监听笔记变化，静默后自动同步 + 提交 + 推送（零第三方依赖）。

监听对象：notes/ 下所有 .md、notes-sources.json、以及配置里 enabled 的外部笔记
（也就是 D:\\笔记\\ 里的 Typora 原稿）。不监听生成的 sync-*.md，避免自己触发自己。

日常用法：什么都不用做 —— 开机后由「启动」文件夹自动拉起（带 --initial 自检一次），
在 Typora 里 Ctrl+S 保存，静默 30 秒后自动同步、提交、push，
GitHub Actions 约 1 分钟后把新内容发到博客。

发布失败（网络抖动、凭据临时失效）会每 60→120→…→300 秒自动重试，
不必等下一次记笔记；每次结果写入 tools/autosync.log 便于排查。

手动用法：
  npm run watch                    # 前台运行（Ctrl+C 停止）
  npm run watch -- --no-push       # 只自动同步+提交，不推送
  npm run watch -- --debounce 15   # 改静默时长
  python tools/watch_notes.py --initial --once   # 启动时立即跑一次（自检）

本机已用 gh auth login + gh auth setup-git 配好凭据，push 不需要密码或 PAT。
"""
import argparse
import ctypes
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG = os.path.join(ROOT, 'notes-sources.json')
PUBLISH = os.path.join(HERE, 'publish.py')
LOG = os.path.join(HERE, 'autosync.log')   # *.log 已在 .gitignore，不会进仓库


def log(msg):
    """pythonw 无控制台，把发布结果落盘，方便排查「为什么网站没更新」。"""
    line = '[%s] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg)
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except OSError:
        pass


def single_instance():
    """Windows 命名互斥体：开机自启和手动运行时不要起两个发布进程。"""
    if os.name != 'nt':
        return True
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.CreateMutexW(None, False, 'Local\\PwnNotesAutoSync')
    return ctypes.get_last_error() != 183


def load_sources():
    try:
        with open(CONFIG, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {'notes_dir': 'notes', 'external': []}


def watched_files(cfg):
    paths = {CONFIG}
    notes_dir = os.path.join(ROOT, cfg.get('notes_dir', 'notes'))
    for dirpath, dirnames, filenames in os.walk(notes_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fn in filenames:
            if fn.lower().endswith('.md'):
                paths.add(os.path.join(dirpath, fn))
    for item in cfg.get('external', []):
        if not item.get('enabled'):
            continue
        raw = item.get('path', '')
        p = raw if os.path.isabs(raw) else os.path.normpath(os.path.join(ROOT, raw))
        if os.path.isfile(p):
            paths.add(p)
        elif os.path.isdir(p):
            for fn in os.listdir(p):
                if fn.lower().endswith('.md'):
                    paths.add(os.path.join(p, fn))
    return paths


def snapshot(cfg):
    sig = {}
    for p in sorted(watched_files(cfg)):
        try:
            st = os.stat(p)
            sig[p] = (st.st_mtime_ns, st.st_size)
        except OSError:
            pass
    return sig


def do_publish(push):
    # --prune：源被禁用/删除时，自动撤下对应文章和图片
    cmd = [sys.executable, PUBLISH, '--prune']
    if push:
        cmd.append('--push')
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True,
                           text=True, errors='replace')
    except OSError as e:
        log('无法启动发布脚本：%s' % e)
        return False
    out = ((r.stdout or '') + (r.stderr or '')).strip()
    log('发布脚本退出码 %d\n%s' % (r.returncode, out[-2500:]))
    return r.returncode == 0


def main():
    ap = argparse.ArgumentParser(description='监听笔记变化并自动发布')
    ap.add_argument('--interval', type=float, default=3.0, help='轮询间隔秒')
    ap.add_argument('--debounce', type=float, default=30.0, help='静默多少秒后才发布')
    ap.add_argument('--no-push', action='store_true', help='只自动提交，不推送')
    ap.add_argument('--initial', action='store_true', help='启动时立即同步一次')
    ap.add_argument('--once', action='store_true', help='处理完一次变化就退出（自检用）')
    args = ap.parse_args()

    if not single_instance():
        log('已有自动同步实例在运行，本次退出。')
        return 0

    cfg = load_sources()
    push_enabled = not args.no_push
    prev = snapshot(cfg)
    dirty = args.initial
    last_change = time.time()
    retry_at = 0.0
    retry_delay = 60.0

    log('监听启动：间隔 %.1fs | 静默 %.1fs | 推送 %s | 开机自检 %s'
        % (args.interval, args.debounce, '开' if push_enabled else '关',
           '开' if args.initial else '关'))
    log('在 Typora 里保存 pwn题目.md / 汇编语言：.md 就会自动上线。日志：%s' % LOG)

    while True:
        now = time.time()
        # 发布失败时按 retry_at 定时重试，不再依赖「下一次笔记改动」
        due = (dirty and now - last_change >= args.debounce) or (retry_at and now >= retry_at)
        if due:
            is_retry = bool(retry_at)
            dirty = False
            retry_at = 0.0
            log('--- 开始发布 %s%s ---'
                % (time.strftime('%H:%M:%S'), '（失败重试）' if is_retry else ''))
            if do_publish(push_enabled):
                retry_delay = 60.0
                log('--- 发布完成，等待下一次保存 ---')
            else:
                retry_at = now + retry_delay
                retry_delay = min(retry_delay * 2, 300.0)
                log('--- 发布未完成（多为网络波动），%.0f 秒后自动重试 ---' % (retry_at - now))
            if args.once:
                return 0
        time.sleep(max(0.2, args.interval))
        cur = snapshot(load_sources())
        if cur != prev:
            added = len(set(cur) - set(prev))
            removed = len(set(prev) - set(cur))
            changed = sum(1 for k in set(cur) & set(prev) if cur[k] != prev[k])
            log('检测到改动：新增 %d / 删除 %d / 修改 %d，等待静默…'
                % (added, removed, changed))
            prev = cur
            dirty = True
            last_change = time.time()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\n已停止监听。')
        sys.exit(0)
