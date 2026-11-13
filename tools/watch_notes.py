#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""后台监听笔记变化，静默后自动同步 + 提交 + 推送（零第三方依赖）。

监听对象：notes/ 下所有 .md、notes-sources.json、以及配置里 enabled 的外部笔记
（也就是 D:\\笔记\\ 里的 Typora 原稿）。不监听生成的 sync-*.md，避免自己触发自己。

日常用法：什么都不用做 —— 开机后由「启动」文件夹自动拉起，
在 Typora 里 Ctrl+S 保存，静默 30 秒后自动同步、提交、push，
GitHub Actions 约 1 分钟后把新内容发到博客。

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
    cmd = [sys.executable, PUBLISH]
    if push:
        cmd.append('--push')
    r = subprocess.run(cmd, cwd=ROOT)
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
        print('已有自动同步实例在运行，本次退出。')
        return 0

    cfg = load_sources()
    push_enabled = not args.no_push
    prev = snapshot(cfg)
    dirty = args.initial
    last_change = time.time()

    print('监听中：notes/ 与已启用的外部笔记（含 D:\\笔记\\*.md） | 间隔 %.1fs | 静默 %.1fs | 推送 %s'
          % (args.interval, args.debounce, '开' if push_enabled else '关'))
    print('在 Typora 里保存笔记就会自动上线；按 Ctrl+C 停止。')
    if push_enabled:
        print('凭据已由 gh auth setup-git 配好，不需要密码或 PAT。')

    while True:
        if dirty and (time.time() - last_change) >= args.debounce:
            dirty = False
            print('\n--- 检测到改动，开始发布 %s ---' % time.strftime('%H:%M:%S'))
            if not do_publish(push_enabled):
                print('\n[提示] 本次发布未完成（多为网络波动），下次改动会重试。')
            print('--- 发布流程结束 ---\n')
            if args.once:
                return 0
        time.sleep(max(0.2, args.interval))
        cur = snapshot(load_sources())
        if cur != prev:
            added = len(set(cur) - set(prev))
            removed = len(set(prev) - set(cur))
            changed = sum(1 for k in set(cur) & set(prev) if cur[k] != prev[k])
            print('检测到改动：新增 %d / 删除 %d / 修改 %d，等待静默…'
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
