#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把「笔记投递区」转换成 Hexo 文章（零第三方依赖，本地 / GitHub Actions 通用）。

设计要点
--------
* notes/ 下一个 .md = 一篇文章；配置了 split-h1 的源按一级标题拆分，
  并且**跳过 ``` 代码块里的 # 注释**（pwn 笔记里大量 Python 注释以 # 开头）。
* 自动补 front matter：标题 / 日期 / 分类 / 标签，按 Pwn 关键词推断。
* Typora 绝对路径图片自动复制到文章资源目录，链接改写成相对路径；
  外部笔记在 stage 阶段先把图片搬进 notes/external/<name>/assets/，
  让提交到仓库的原稿自包含，CI 才能重新生成。
* 幂等：正文里写 <!-- sync-hash: ... -->，源文本没变就 SKIP；
  重写时保留原 date。只管理 source/_posts/sync-*.md，不碰手写文章。
* 外部笔记源**只读**：不修改、不移动、不删除用户的原文件。

用法
----
  python tools/sync_notes.py --dry              # 只预览
  python tools/sync_notes.py                   # 同步（含 stage 外部源）
  python tools/sync_notes.py --ci              # CI：只处理仓库内 notes/，不碰外部路径
  python tools/sync_notes.py --prune           # 额外清理源已消失的生成文章
  python tools/sync_notes.py --force           # 不管 hash，全部重写
  python tools/sync_notes.py --json            # 机器可读报告（供 publish.py 使用）
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT, 'notes-sources.json')
POSTS = os.path.join(ROOT, 'source', '_posts')
PREFIX = 'sync'

HASH_RE = re.compile(r'<!--\s*sync-hash:\s*([0-9a-f]{64})\s*-->')
DATE_RE = re.compile(r'^date:\s*(.+?)\s*$', re.M)
IMG_RE = re.compile(r'!\[([^\]]*)\]\(([^)]+)\)')
H1_RE = re.compile(r'^#\s+(.+?)\s*$')

# 赛事 -> 二级分类
EVENTS = [
    ('ciscn', 'CISCN'), ('buuctf', 'BUUCTF'), ('roarctf', 'RoarCTF'),
    ('0ctf', '0CTF'), ('hitcon', 'HITCON'), ('gyctf', 'GYCTF'),
    ('zjctf', 'ZJCTF'), ('hgame', 'Hgame'), ('newstar', 'NewStar'),
    ('ctfshow', 'ctfshow'), ('攻防世界', '攻防世界'), ('琢光杯', '琢光杯'),
    ('单身杯', '单身杯'), ('how2heap', 'how2heap'), ('v&n', 'V&N'),
]
# 方向关键词（顺序即优先级）
DIRECTIONS = [
    ('格式化字符串', r'格式化字符串|format string|fmtstr|printf\s*\('),
    ('堆', r'heap|tcache|fastbin|unsorted\s*bin|smallbin|largebin|unlink|malloc|free\s*\(|chunk|堆|house\s+of|off\s+by\s+null|bins'),
    ('栈', r'\brop\b|ret2|canary|stack|栈溢出|栈|gadget'),
    ('Misc', r'\bmisc\b|隐写|摩斯|流量分析|取证|编码|压缩包'),
    ('逆向', r'\breverse\b|ida|反汇编|汇编|逆向'),
]
# 手法标签（显示名, 匹配正则）
TAG_WORDS = [
    ('tcache', r'\btcache\b'), ('fastbin', r'\bfastbin\b'),
    ('unsorted-bin', r'unsorted\s*bin'), ('unlink', r'\bunlink\b'),
    ('UAF', r'\buaf\b|use.after.free'), ('double-free', r'double\s*free'),
    ('HouseOfSpirit', r'house\s+of\s+spirit'), ('HouseOfForce', r'house\s+of\s+force'),
    ('off-by-null', r'off\s+by\s+(null|one)'), ('one-gadget', r'one_gadget|one.gadget'),
    ('malloc-hook', r'__malloc_hook'), ('free-hook', r'__free_hook'),
    ('IO-FILE', r'io_file|_io_file|fsop'), ('malloc-consolidate', r'malloc_consolidate'),
    ('fmtstr-payload', r'fmtstr_payload'), ('格式化字符串', r'格式化字符串|format string'),
    ('ROP', r'\brop\b|ret2libc'), ('canary', r'canary'),
    ('堆风水', r'堆风水|heap feng shui|heap grooming'),
    ('tcache-stash', r'tcache\s*stash|stash'),
]
REWRITE_INDICATORS = r'复现|writeup|\bwp\b|题面|flag\{|靶机|exp\b|附件|challenge|getshell|打远端'


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def yaml_str(s):
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ') + '"'


def read_text(path):
    for enc in ('utf-8-sig', 'utf-8', 'gb18030'):
        try:
            with open(path, 'r', encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def parse_front_matter(text):
    """返回 (meta dict, body)。只解析简单的 key: value 与 key: [a, b]。"""
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
        m = re.match(r'^([A-Za-z_][\w-]*):\s*(.*)$', line)
        if m:
            meta[m.group(1)] = m.group(2).strip()
    return meta, '\n'.join(lines[end + 1:]).lstrip('\n')


def parse_list(raw):
    if not raw:
        return []
    raw = raw.strip().strip('[]')
    return [x.strip().strip('"\'') for x in re.split(r'[,，]+', raw) if x.strip()]


def clean_title(raw):
    t = raw.strip()
    t = re.sub(r'[*`_]+', '', t)
    t = re.sub(r'^#+\s*', '', t).strip()
    t = t.strip('=—- ').strip()
    return t or '未命名'


def safe_name(name):
    base = os.path.basename(name.replace('\\', '/'))
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', base)
    return safe or ('img_' + hashlib.sha1(base.encode('utf-8')).hexdigest()[:8])


def resolve_image(raw, src_dir):
    """把 Typora 的 Windows 绝对路径 / file:// / 相对路径解析成本地路径。"""
    p = raw.strip()
    if p.startswith('<') and p.endswith('>'):
        p = p[1:-1].strip()
    p = p.split(' "')[0].strip()          # 去掉可选的 "title"
    p = urllib.parse.unquote(p)
    if p.lower().startswith('file://'):
        p = urllib.parse.urlparse(p).path
        if re.match(r'^/[A-Za-z]:/', p):
            p = p[1:]
    p = p.replace('\\', '/')
    if not os.path.isabs(p):
        p = os.path.join(src_dir, p)
    return os.path.normpath(p)


def load_config():
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


# --------------------------------------------------------------------------
# 阶段 1：把外部只读笔记连同图片搬进 notes/external/（CI 不做）
# --------------------------------------------------------------------------
def stage_one_file(src, dest_dir, report):
    """复制单个 md 到投递区，并把绝对路径图片改成 assets/ 相对路径。"""
    os.makedirs(dest_dir, exist_ok=True)
    assets_dir = os.path.join(dest_dir, 'assets')
    text = read_text(src)
    src_dir = os.path.dirname(os.path.abspath(src))
    changed = False

    def repl(m):
        nonlocal changed
        alt, raw = m.group(1), m.group(2)
        real = resolve_image(raw, src_dir)
        if not os.path.isfile(real):
            report['missing_images'].append('%s -> %s' % (os.path.basename(src), raw))
            return m.group(0)
        name = safe_name(real)
        os.makedirs(assets_dir, exist_ok=True)
        dst = os.path.join(assets_dir, name)
        if not os.path.isfile(dst) or os.path.getsize(dst) != os.path.getsize(real):
            shutil.copy2(real, dst)
            report['copied_images'] += 1
        changed = True
        return '![%s](assets/%s)' % (alt, name)

    new_text = IMG_RE.sub(repl, text)
    dest = os.path.join(dest_dir, os.path.basename(src))
    if not os.path.isfile(dest) or read_text(dest) != new_text:
        write_text(dest, new_text)
        report['staged'] += 1
    return changed


def stage_external(cfg, report):
    notes_dir = os.path.join(ROOT, cfg.get('notes_dir', 'notes'))
    for item in cfg.get('external', []):
        if not item.get('enabled'):
            continue
        raw_path = item.get('path', '')
        path = raw_path if os.path.isabs(raw_path) else os.path.normpath(os.path.join(ROOT, raw_path))
        name = re.sub(r'[^a-z0-9-]', '', item.get('name', 'ext').lower()) or 'ext'
        dest_dir = os.path.join(notes_dir, 'external', name)
        if os.path.isfile(path):
            stage_one_file(path, dest_dir, report)
        elif os.path.isdir(path):
            md_files = sorted(f for f in os.listdir(path)
                              if f.lower().endswith('.md') and not f.startswith('_'))
            for f in md_files:
                stage_one_file(os.path.join(path, f), dest_dir, report)
        else:
            report['warnings'].append('外部源不存在，已跳过：%s' % raw_path)


# --------------------------------------------------------------------------
# 阶段 2：notes/ -> 文章单元
# --------------------------------------------------------------------------
class Unit(object):
    __slots__ = ('key', 'source_name', 'title', 'raw', 'src_dir',
                 'meta', 'cfg_cat', 'cfg_sub')

    def __init__(self, key, source_name, title, raw, src_dir,
                 meta=None, cfg_cat=None, cfg_sub=None):
        self.key = key
        self.source_name = source_name
        self.title = title
        self.raw = raw
        self.src_dir = src_dir
        self.meta = meta or {}
        self.cfg_cat = cfg_cat
        self.cfg_sub = cfg_sub

    @property
    def hash(self):
        return hashlib.sha256((self.key + '\n' + self.raw).encode('utf-8')).hexdigest()

    @property
    def slug(self):
        ascii_part = re.sub(r'[^A-Za-z0-9]+', '-', self.title).strip('-').lower()[:40].strip('-')
        if len(ascii_part) < 3:
            ascii_part = hashlib.sha1(self.title.encode('utf-8')).hexdigest()[:8]
        h = hashlib.sha1(self.key.encode('utf-8')).hexdigest()[:6]
        return '%s-%s-%s-%s' % (PREFIX, self.source_name, ascii_part, h)


def external_rules(cfg, notes_dir):
    """返回 {目录名小写: 配置项}，用于识别 notes/external/<name>/ 下的文件。"""
    out = {}
    for item in cfg.get('external', []):
        name = re.sub(r'[^a-z0-9-]', '', item.get('name', '').lower())
        if name:
            out[name] = item
    return out


def extract_first_h1(text):
    """取正文里第一个非代码块的一级标题当文章标题，并把它从正文移除（避免标题重复）。"""
    out, found = [], None
    in_fence, fence_mark = False, ''
    for line in text.splitlines():
        m_fence = re.match(r'^(`{3,}|~{3,})', line.lstrip())
        if m_fence:
            mark = m_fence.group(1)[0]
            if not in_fence:
                in_fence, fence_mark = True, mark
            elif mark == fence_mark:
                in_fence = False
            out.append(line)
            continue
        m = H1_RE.match(line) if not in_fence else None
        if m and found is None:
            found = clean_title(m.group(1))
            continue
        out.append(line)
    return found, '\n'.join(out)


def split_h1(text, rel, source_name, src_dir, min_chars, cfg_cat, cfg_sub):
    """按一级标题拆分，跳过 fenced code block 内的 # 注释。"""
    units = []
    cur_title = clean_title(os.path.splitext(os.path.basename(rel))[0])
    cur_lines = []
    in_fence = False
    fence_mark = ''
    idx = 0

    def flush():
        nonlocal cur_lines, idx
        body = '\n'.join(cur_lines).strip('\n')
        if len(body.strip()) >= min_chars:
            units.append(Unit('%s#%d' % (rel, idx), source_name, cur_title,
                              body, src_dir, cfg_cat=cfg_cat, cfg_sub=cfg_sub))
            idx += 1
        cur_lines = []

    for line in text.splitlines():
        stripped = line.lstrip()
        m_fence = re.match(r'^(`{3,}|~{3,})', stripped)
        if m_fence:
            mark = m_fence.group(1)[0]
            if not in_fence:
                in_fence, fence_mark = True, mark
            elif mark == fence_mark:
                in_fence = False
            cur_lines.append(line)
            continue
        if not in_fence:
            m = H1_RE.match(line)
            if m:
                flush()
                cur_title = clean_title(m.group(1))
                continue
        cur_lines.append(line)
    flush()
    return units


def collect_units(cfg):
    notes_dir = os.path.join(ROOT, cfg.get('notes_dir', 'notes'))
    rules = external_rules(cfg, notes_dir)
    min_chars = int(cfg.get('min_chars', 160))
    default = cfg.get('default', {})
    units = []
    if not os.path.isdir(notes_dir):
        return units

    for dirpath, dirnames, filenames in os.walk(notes_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        rel_dir = os.path.relpath(dirpath, notes_dir).replace('\\', '/')
        parts = rel_dir.split('/') if rel_dir != '.' else []
        ext_rule = rules.get(parts[1].lower()) if len(parts) >= 2 and parts[0] == 'external' else None
        source_name = parts[1] if (len(parts) >= 2 and parts[0] == 'external') else 'notes'
        mode = ext_rule.get('mode', 'per-file') if ext_rule else 'per-file'
        # 只有外部源配置里显式写了分类才固定；普通投递区笔记一律自动推断
        cat = ext_rule.get('category') if ext_rule else None
        sub = ext_rule.get('sub') if ext_rule else None

        for fn in sorted(filenames):
            if not fn.lower().endswith('.md'):
                continue
            if fn.startswith('_') or fn.upper().startswith('README'):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, ROOT).replace('\\', '/')
            text = read_text(full)
            meta, body = parse_front_matter(text)
            if mode == 'split-h1':
                units.extend(split_h1(body, rel, source_name, os.path.dirname(full),
                                      min_chars, cat, sub))
            else:
                h1_title, body = extract_first_h1(body)
                title = (meta.get('title') or h1_title or
                         clean_title(os.path.splitext(fn)[0])).strip('"\'')
                u = Unit(rel, source_name, title, body.strip('\n'),
                         os.path.dirname(full), meta=meta, cfg_cat=cat, cfg_sub=sub)
                units.append(u)
    return units


# --------------------------------------------------------------------------
# 阶段 3：推断元信息 / 搬运图片 / 渲染
# --------------------------------------------------------------------------
def infer(unit, cfg):
    default = cfg.get('default', {})
    meta = unit.meta
    if meta.get('categories'):
        cats = parse_list(meta['categories'])
    else:
        blob = (unit.title + ' ' + unit.raw[:4000]).lower()
        event = next((label for needle, label in EVENTS if needle in blob), '')
        is_writeup = bool(re.search(REWRITE_INDICATORS, blob, re.I)) or bool(event)
        cat = unit.cfg_cat or ('题目复现' if is_writeup else default.get('category', '知识点'))
        sub = unit.cfg_sub
        if not sub:
            if is_writeup:
                sub = event or '其他赛事'
            else:
                sub = next((label for label, pat in DIRECTIONS
                            if re.search(pat, blob, re.I)), default.get('sub', '未分类'))
        cats = [cat, sub] if cat and sub else [cat]

    if meta.get('tags'):
        tags = parse_list(meta['tags'])
    else:
        blob = (unit.title + ' ' + unit.raw).lower()
        tags = [label for label, pat in TAG_WORDS if re.search(pat, blob, re.I)]
        m = re.search(r'libc[- ]?2\.(\d{2})', blob, re.I)
        if m:
            v = 'glibc2.' + m.group(1)
            if v not in tags:
                tags.append(v)
        tags = tags[:8]
    return cats, tags


def process_images(text, slug, src_dir, dry, report):
    """复制图片到 source/_posts/<slug>/，并改写链接。返回新文本。"""
    asset_dir = os.path.join(POSTS, slug)

    def repl(m):
        alt, raw = m.group(1), m.group(2)
        if raw.strip().startswith(('http://', 'https://', 'data:')):
            return m.group(0)
        real = resolve_image(raw, src_dir)
        if not os.path.isfile(real):
            report['missing_images'].append('%s -> %s' % (slug, raw))
            return m.group(0)
        name = safe_name(real)
        dst = os.path.join(asset_dir, name)
        if not dry and (not os.path.isfile(dst) or os.path.getsize(dst) != os.path.getsize(real)):
            os.makedirs(asset_dir, exist_ok=True)
            shutil.copy2(real, dst)
            report['copied_images'] += 1
        # hexo-renderer-marked 的 postAsset 会自己拼 postPath，
        # 这里必须只写文件名；写成 ./<slug>/<name> 会拼出双层目录导致 404
        return '![%s](%s)' % (alt, name)

    return IMG_RE.sub(repl, text)


def render(unit, cfg, old_date, dry, report):
    cats, tags = infer(unit, cfg)
    body = process_images(unit.raw, unit.slug, unit.src_dir, dry, report)
    date = old_date or unit.meta.get('date') or datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', date.strip()):
        date = date.strip() + ' 00:00:00'

    fm = ['---', 'title: %s' % yaml_str(unit.title), 'date: %s' % date,
          'categories:']
    fm += ['  - %s' % yaml_str(c) for c in cats]
    fm.append('tags: [%s]' % ', '.join(yaml_str(t) for t in tags))
    fm += ['---', '',
           '<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->',
           '<!-- sync-source: %s -->' % unit.key, '']
    return '\n'.join(fm) + body.rstrip() + '\n\n<!-- sync-hash: %s -->\n' % unit.hash


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def scan_existing():
    """返回 {hash: (path, date)} 与 全部 sync-*.md 路径列表。"""
    by_hash, all_paths = {}, []
    if not os.path.isdir(POSTS):
        return by_hash, all_paths
    for fn in sorted(os.listdir(POSTS)):
        if not (fn.startswith(PREFIX + '-') and fn.endswith('.md')):
            continue
        path = os.path.join(POSTS, fn)
        all_paths.append(path)
        text = read_text(path)
        m = HASH_RE.search(text)
        d = DATE_RE.search(text)
        if m:
            by_hash[m.group(1)] = (path, d.group(1).strip('"\'') if d else None)
    return by_hash, all_paths


def run(stage=True, dry=False, force=False, prune=False, ci=False, quiet=False):
    report = {'units': 0, 'written': 0, 'skipped': 0, 'pruned': 0, 'staged': 0,
              'copied_images': 0, 'missing_images': [], 'warnings': [],
              'posts': [], 'dry': dry, 'changed': False}
    cfg = load_config()
    if ci:
        stage = False
    if stage and not dry:
        stage_external(cfg, report)
    elif stage and dry and any(x.get('enabled') for x in cfg.get('external', [])):
        report['warnings'].append(
            '--dry 不会暂存外部笔记；去掉 --dry 后才复制到 notes/external/ 并同步')

    by_hash, all_paths = scan_existing()
    units = collect_units(cfg)
    report['units'] = len(units)
    expected = set()
    seen_slugs = set()

    for unit in units:
        h = unit.hash
        expected.add(h)
        if len(unit.raw.strip()) == 0:
            continue
        if unit.slug in seen_slugs:
            report['warnings'].append('slug 冲突，已跳过：%s' % unit.key)
            continue
        seen_slugs.add(unit.slug)
        old = by_hash.get(h)
        if old and not force:
            report['skipped'] += 1
            report['posts'].append(('SKIP', unit.slug, unit.title))
            continue
        old_date = old[1] if old else None
        content = render(unit, cfg, old_date, dry, report)
        dest = os.path.join(POSTS, unit.slug + '.md')
        if old and old[0] != dest:
            if not dry:
                os.remove(old[0])
        if not dry:
            write_text(dest, content)
        report['written'] += 1
        report['posts'].append(('DRY' if dry else 'WRITE', unit.slug, unit.title))

    if prune:
        for path in all_paths:
            text = read_text(path)
            m = HASH_RE.search(text)
            if not m:
                continue
            if m.group(1) not in expected:
                if not dry:
                    os.remove(path)
                    asset = os.path.join(POSTS, os.path.splitext(os.path.basename(path))[0])
                    if os.path.isdir(asset):
                        for f in os.listdir(asset):        # 只删文件，不递归子目录
                            fp = os.path.join(asset, f)
                            if os.path.isfile(fp):
                                os.remove(fp)
                        try:
                            os.rmdir(asset)
                        except OSError:
                            pass                          # 里面还有用户自己的东西，留着
                report['pruned'] += 1
                report['posts'].append(('PRUNE', os.path.basename(path), ''))

    report['changed'] = bool(report['written'] or report['pruned'] or
                             report['staged'] or report['copied_images'])
    if not quiet:
        print_report(report)
    return report


def print_report(r):
    for action, slug, title in r['posts']:
        print('%-6s %-58s %s' % (action, slug, title[:36]))
    print('')
    print('源单元 %d 个 | %s%d 篇 | 跳过 %d | 清理 %d | 外部暂存 %d | 图片复制 %d'
          % (r['units'], '计划生成 ' if r['dry'] else '生成 ',
             r['written'], r['skipped'], r['pruned'], r['staged'], r['copied_images']))
    if r['missing_images']:
        print('\n找不到的图片（已保留原链接）：')
        for x in r['missing_images'][:10]:
            print('  ! ' + x)
        if len(r['missing_images']) > 10:
            print('  ... 还有 %d 条' % (len(r['missing_images']) - 10))
    for w in r['warnings']:
        print('警告：' + w)


def main():
    ap = argparse.ArgumentParser(description='笔记投递区 -> Hexo 文章')
    ap.add_argument('--dry', action='store_true', help='只预览，不写文件')
    ap.add_argument('--force', action='store_true', help='忽略 hash，全部重写')
    ap.add_argument('--prune', action='store_true', help='删除源已消失的生成文章')
    ap.add_argument('--ci', action='store_true', help='CI 模式：不读取仓库外的笔记源')
    ap.add_argument('--no-stage', action='store_true', help='跳过外部源暂存')
    ap.add_argument('--json', action='store_true', help='输出 JSON 报告')
    args = ap.parse_args()
    try:
        r = run(stage=not args.no_stage, dry=args.dry, force=args.force,
                prune=args.prune, ci=args.ci, quiet=args.json)
    except Exception as e:
        print('同步失败：%s: %s' % (type(e).__name__, e), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
