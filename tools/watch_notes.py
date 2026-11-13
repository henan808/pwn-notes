#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""后台监听笔记变化，静默一段时间后自动同步 + 提交 + 推送（零第三方依赖）。

监听对象：notes/ 下所有 .md、notes-sources.json、以及配置里 enabled 的外部笔记。
不监听生成出来的 source/_posts/sync-*.md，避免自己触发自己。

用法：
  npm run watch                    # 保存笔记后自动发布（默认 push）
  npm run watch -- --no-push       # 只自动同步+提交，不推送
  npm run watch -- --debounce 15   # 静默 15 秒才发布，避免写一半就推
  python tools/watch_notes.py --initial --once   # 启动时先跑一次（自检用）

首次 push 若因凭据问题失败，会自动降级为「只提交不推送」并继续监听，不会反复报错刷屏。
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG = os.path.join(ROOT, 'notes-sources.json')
PUBLISH = os.path.join(HERE, 'publish.py')


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
    ap.add_argument('--interval', type=float, default=2.0, help='轮询间隔秒')
    ap.add_argument('--debounce', type=float, default=8.0, help='静默多少秒后才发布')
    ap.add_argument('--no-push', action='store_true', help='只自动提交，不推送')
    ap.add_argument('--initial', action='store_true', help='启动时立即同步一次')
    ap.add_argument('--once', action='store_true', help='处理完一次变化就退出（自检用）')
    args = ap.parse_args()

    cfg = load_sources()
    push_enabled = not args.no_push
    prev = snapshot(cfg)
    dirty = args.initial
    last_change = time.time()

    print('监听中：notes/ 与已启用的外部笔记 | 间隔 %.1fs | 静默 %.1fs | 推送 %s'
          % (args.interval, args.debounce, '开' if push_enabled else '关'))
    print('按 Ctrl+C 停止。')
    if push_enabled:
        print('提示：push 需要系统已配好 PAT / SSH key；脚本不保存任何凭据。')

    while True:
        if dirty and (time.time() - last_change) >= args.debounce:
            dirty = False
            print('\n--- 检测到改动，开始发布 %s ---' % time.strftime('%H:%M:%S'))
            ok = do_publish(push_enabled)
            if not ok and push_enabled:
                push_enabled = False
                print('\n[自动降级] 推送失败，之后只同步+提交，不再尝试推送。')
                print('配好凭据后重新运行 npm run watch 即可恢复自动推送。')
            print('--- 发布流程结束 ---\n')
            if args.once:
                return 0
        if args.once and not dirty and not args.initial:
            # once 模式下等待外部改动
            pass
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
