#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把已有的 WP/实战记录/Pwn/*.md 题解导入成 Hexo 文章。

原文件的 YAML front matter（题名/赛事/方向/技术栈/日期/flag…）会被转换成
Hexo 需要的 title / date / categories / tags，并作为引用块保留在正文顶部；
正文一字不改。

用法：
  python tools/import_from_wp.py --dry       # 只打印计划
  python tools/import_from_wp.py             # 写入 source/_posts/imported-*.md
  python tools/import_from_wp.py --force     # 覆盖已导入的文件
  python tools/import_from_wp.py --src <别的题解目录>
"""
import argparse
import datetime
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS = os.path.join(ROOT, 'source', '_posts')
DEFAULT_SRC = os.path.join(os.path.dirname(ROOT), 'WP', '实战记录', 'Pwn')

EVENT_RULES = [
    ('RoarCTF', 'RoarCTF'), ('CISCN', 'CISCN'), ('BUUCTF', 'BUUCTF'),
    ('攻防世界', '攻防世界'), ('ctfshow', 'ctfshow'), ('newstar', 'NewStar'),
    ('琢光杯', '琢光杯'), ('Hgame', 'Hgame'), ('XCTF', 'XCTF'),
]


def yaml_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def split_front_matter(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != '---':
        return {}, text
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == '---':
            end = i
            break
    if end is None:
        return {}, text
    meta = {}
    for line in lines[1:end]:
        m = re.match(r'^([^:#]+):\s*(.*)$', line)
        if m:
            meta[m.group(1).strip()] = m.group(2).strip()
    return meta, '\n'.join(lines[end + 1:]).lstrip('\n')


def guess_event(meta):
    blob = ' '.join([meta.get('赛事', ''), meta.get('题名', ''), meta.get('来源', '')])
    for needle, label in EVENT_RULES:
        if needle.lower() in blob.lower():
            return label
    return '其他赛事'


def parse_tags(meta):
    raw = meta.get('技术栈', '')
    # 只按显式分隔符切，不按空格切：否则 "House of Spirit" 会被切成 3 个垃圾标签
    parts = re.split(r'[/,，、;；]+', raw)
    out = []
    for p in parts:
        p = p.strip()
        if not p or len(p) > 24 or p in ('Pwn', 'pwn', '实战记录'):
            continue
        if p not in out:
            out.append(p)
    # 把 libc 版本也提成标签，方便按版本检索
    for env_key in ('环境', '题名'):
        m = re.search(r'libc[- ]?2\.(\d{2})', meta.get(env_key, ''), re.I)
        if m and 'glibc2.' + m.group(1) not in out:
            out.append('glibc2.' + m.group(1))
    return out[:8]


def build(meta, body, src_name):
    title = meta.get('题名') or os.path.splitext(src_name)[0]
    title = title.strip('[]')
    date = meta.get('日期') or datetime.date.today().isoformat()
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
        date += ' 00:00:00'
    event = guess_event(meta)
    tags = parse_tags(meta)

    fm = ['---', 'title: %s' % yaml_str(title), 'date: %s' % date,
          'categories:', '  - 题目复现', '  - %s' % event,
          'tags: [%s]' % ', '.join(tags), '---', '']

    kept = [k for k in ('赛事', '来源', '方向', '难度', 'flag', '日期', '技术栈',
                        '状态', '环境') if meta.get(k)]
    note = ['> 本文由 `tools/import_from_wp.py` 从 `%s` 导入，正文未改动。' % src_name, '>']
    for k in kept:
        note.append('> - %s：%s' % (k, meta[k]))
    note.append('')
    note.append('<!-- 原始题解元信息保留如上；Hexo 分类/标签见 front matter -->')
    note.append('')

    return '\n'.join(fm + note) + body.rstrip() + '\n'


def main():
    ap = argparse.ArgumentParser(description='导入已有 Pwn 题解为 Hexo 文章')
    ap.add_argument('--src', default=DEFAULT_SRC, help='题解目录')
    ap.add_argument('--dry', action='store_true', help='只打印计划，不写文件')
    ap.add_argument('--force', action='store_true', help='覆盖已存在的 imported-*.md')
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        print('找不到题解目录：%s' % args.src, file=sys.stderr)
        return 1

    files = sorted(f for f in os.listdir(args.src) if f.lower().endswith('.md'))
    if not files:
        print('目录里没有 .md 文件：%s' % args.src, file=sys.stderr)
        return 0

    os.makedirs(POSTS, exist_ok=True)
    written = skipped = 0
    for name in files:
        src = os.path.join(args.src, name)
        with open(src, 'r', encoding='utf-8') as f:
            text = f.read()
        meta, body = split_front_matter(text)
        out_name = 'imported-' + os.path.splitext(name)[0] + '.md'
        dest = os.path.join(POSTS, out_name)
        if os.path.exists(dest) and not args.force:
            print('SKIP  %s（已存在，加 --force 覆盖）' % out_name)
            skipped += 1
            continue
        content = build(meta, body, name)
        print('%s  %-52s  title=%s  cat=题目复现>%s'
              % ('DRY  ' if args.dry else 'WRITE', out_name,
                 meta.get('题名', name)[:28], guess_event(meta)))
        if not args.dry:
            with open(dest, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)
            written += 1
    print('\n源目录：%s' % args.src)
    print('共 %d 篇；%s%d 篇，跳过 %d 篇' %
          (len(files), '计划写入 ' if args.dry else '已写入 ', written if not args.dry else len(files) - skipped, skipped))
    return 0


if __name__ == '__main__':
    sys.exit(main())
