#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""新建一篇 Pwn 笔记：自动写好 Hexo front matter 与图片资源目录。

用法：
  python tools/new_post.py --title "tcache stash 机制" --type knowledge \
      --sub 堆 --tags tcache,glibc2.27 --slug tcache-stash
  python tools/new_post.py --title "[RoarCTF 2019] easyheap" --type writeup \
      --sub RoarCTF --tags unlink,libc2.23,HouseOfSpirit --slug roarctf2019-easyheap
  python tools/new_post.py --title "随便记一笔" --type post

不传 --slug 时：标题含英文就用英文生成 slug，纯中文标题用 note-时间戳。
"""
import argparse
import datetime
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS = os.path.join(ROOT, 'source', '_posts')

TYPE_MAP = {
    'knowledge': ('知识点', '堆'),
    'writeup': ('题目复现', 'BUUCTF'),
    'post': ('指南', None),
    'tool': ('工具与环境', None),
}

BODY = {
    'knowledge': """
## 一句话结论

## 机制说明

## 关键数据结构

## 版本差异（2.23 / 2.27 / 2.31+）

## 调试验证

```gdb
# pwndbg 命令与关键回显
```

## 失败路径与坑

## 参考
""",
    'writeup': """
> 题名：
> 赛事 / 平台：
> 方向 / 难度：
> 附件 / 靶机：
> flag 格式：
> libc 版本：
> 技术栈：

## 一、题面

## 二、思路

## 三、关键步骤

## 四、核心脚本

```python
# 可运行 exp
```

## 五、坑点

## 六、复盘

> 证据边界：是否实测、flag 来自哪里。
""",
    'post': "\n## 正文\n",
    'tool': "\n## 场景\n\n## 命令 / 配置\n\n## 坑\n",
}


def yaml_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def make_slug(title, user_slug):
    if user_slug:
        return re.sub(r'[^a-zA-Z0-9_-]+', '-', user_slug).strip('-').lower()
    ascii_part = re.sub(r'[^a-zA-Z0-9]+', '-', title).strip('-').lower()
    if len(ascii_part) >= 3:
        return ascii_part[:60].strip('-')
    return 'note-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S')


def main():
    ap = argparse.ArgumentParser(description='新建 Pwn 笔记')
    ap.add_argument('--title', required=True, help='文章标题')
    ap.add_argument('--type', default='post', choices=sorted(TYPE_MAP), help='文章类型')
    ap.add_argument('--sub', default='', help='二级分类，如 堆 / BUUCTF / CISCN')
    ap.add_argument('--tags', default='', help='逗号分隔的标签')
    ap.add_argument('--slug', default='', help='文件名（英文），省略则自动生成')
    ap.add_argument('--date', default='', help='YYYY-MM-DD HH:MM:SS，默认当前时间')
    ap.add_argument('--force', action='store_true', help='允许覆盖同名文件')
    args = ap.parse_args()

    cat1, default_sub = TYPE_MAP[args.type]
    sub = args.sub or default_sub
    tags = [t.strip() for t in args.tags.split(',') if t.strip()]
    date = args.date or datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    slug = make_slug(args.title, args.slug)

    os.makedirs(POSTS, exist_ok=True)
    path = os.path.join(POSTS, slug + '.md')
    if os.path.exists(path) and not args.force:
        print('已存在，未覆盖：%s（加 --force 覆盖）' % path, file=sys.stderr)
        return 1

    fm = ['---', 'title: %s' % yaml_str(args.title), 'date: %s' % date, 'categories:',
          '  - %s' % cat1]
    if sub:
        fm.append('  - %s' % yaml_str(sub) if any(c in sub for c in ':#[]{}') else '  - %s' % sub)
    fm.append('tags: [%s]' % ', '.join(tags))
    fm.append('---')
    fm.append('')

    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(fm) + BODY[args.type])

    asset = os.path.join(POSTS, slug)
    os.makedirs(asset, exist_ok=True)
    keep = os.path.join(asset, '.gitkeep')
    if not os.path.exists(keep):
        with open(keep, 'w', encoding='utf-8') as f:
            f.write('')

    print('已创建：%s' % path)
    print('图片目录：%s' % asset)
    print('分类：%s%s' % (cat1, ' > ' + sub if sub else ''))
    print('标签：%s' % (', '.join(tags) or '（空）'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
