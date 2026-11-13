---
title: "misc"
date: 2026-11-13 19:08:04
categories:
  - "知识点"
  - "Misc"
tags: []
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-misc/MISC.md -->
## 白洞

改后缀成压缩包文件，真神了看半天就不知道改后缀。

![image-20261025214811245](/pwn-notes/images/notes/image-20261025214811245.png)

Black holes hide matter, but whiteouts hide history.

![image-20261025214955686](/pwn-notes/images/notes/image-20261025214955686.png)

这是啥，真没见过

docker镜像有关的，而且还是whiteouts机制

![image-20261025220622234](/pwn-notes/images/notes/image-20261025220622234.png)

![image-20261025220640106](/pwn-notes/images/notes/image-20261025220640106.png)

```
# 读取第一段 flag
tar -xOf .\blobs\sha256\c5b5829007eb26e105b5477170c3b066918fe48df609e5047888c8106933cd75 root/.wh.treasure.txt

# 读取第二段 flag
tar -xOf .\blobs\sha256\ceee781106e71dbef68bf980e6981c244ab17724e3d1b6f98ce9793a59a29e8b root/.wh.hint.txt
```

```
 tar -xzOf .\blobs\sha256\96009077d31ee0ea49fcc096a64d3979315d859338f8e3467b90899ea037c896 root/.wh.treasure.txt
flag{lay
PS D:\misc\题目\zip> tar -xzOf .\blobs\sha256\c5b5829007eb26e105b5477170c3b066918fe48df609e5047888c8106933cd75 root/.wh.hint.txt
er_cake}
PS D:\misc\题目\zip>
```

flag{layer_cake}

## 看不见的信

主要就是010打开会看见在文件末尾

![image-20261025222135466](/pwn-notes/images/notes/image-20261025222135466.png)

![image-20261025222246029](/pwn-notes/images/notes/image-20261025222246029.png)

### 零宽字符解码脚本

```python
# 读取文本内容
with open("隐写文本.txt", "r", encoding="utf-8") as f:
    text = f.read()

binary_str = ""
for char in text:
    if char == "\u200b":   # 零宽空格 → 0
        binary_str += "0"
    elif char == "\u200c": # 零宽非连字符 → 1
        binary_str += "1"
    # 其他可见字符直接忽略

# 按8位分割，转成ASCII字符
flag = ""
for i in range(0, len(binary_str), 8):
    byte = binary_str[i:i+8]
    if len(byte) == 8:
        flag += chr(int(byte, 2))

print(flag)
```

## 我的光标去哪了

![image-20261025222923677](/pwn-notes/images/notes/image-20261025222923677.png)

这都是啥

![image-20261025223118023](/pwn-notes/images/notes/image-20261025223118023.png)

看来用010打开是对的，但是不知道啥意思

### ANSI CSI序列？是啥

![image-20261025223442148](/pwn-notes/images/notes/image-20261025223442148.png)

![image-20261025224618442](/pwn-notes/images/notes/image-20261025224618442.png)

原来只需要cat一下就行了

![image-20261025224643083](/pwn-notes/images/notes/image-20261025224643083.png)

# 自画像

数学家小明临终前留下了一张"自画像" `self_portrait.png`，他反复念叨：

> "我的tupper公式，会画出它自己。"

据说他想说的话就藏在这张图里。你能读懂吗？

## Tupper公式：找k值

额，tupper好像就只是找一个k值，10进制的。没脚本，那就

```python
# -*- coding: utf-8 -*-
# Tupper 公式位图尺寸：宽106像素，高17像素
WIDTH, HEIGHT = 106, 17


def extract_hex_from_png(file_path: str) -> str:
    """
    从 PNG 文件尾部（IEND 数据块之后）提取隐藏的十六进制字符串
    PNG 文件以 IEND 块为正式结尾，块后附加的数据属于隐写内容
    """
    with open(file_path, 'rb') as f:
        raw_data = f.read()
    
    # 定位 IEND 块起始位置，偏移 8 字节跳过整个 IEND 块（4字节类型+4字节CRC）
    iend_pos = raw_data.index(b'IEND')
    hidden_data = raw_data[iend_pos + 8:]
    
    # 去除首尾空白字符，转为ASCII字符串返回
    return hidden_data.strip().decode('ascii')


def render_tupper(n: int) -> None:
    """
    纯位运算实现 Tupper 自我指涉公式渲染，输出字符画
    附带自动裁剪四周空白的美化逻辑
    """
    lines = []
    # 从顶部到底部逐行渲染（v=16 对应图像最上方，v=0 对应最下方）
    for v in range(HEIGHT - 1, -1, -1):
        row = ''
        for x in range(WIDTH):
            # 核心：判断整数n的第 (17*x + v) 个二进制位是否为1
            bit = (n >> (17 * x + v)) & 1
            row += '██' if bit else '  '
        lines.append(row.rstrip())

    # ========== 美化处理：裁剪四周空白 ==========
    # 1. 移除顶部连续空行
    while lines and not lines[0].strip():
        lines.pop(0)
    # 2. 移除底部连续空行
    while lines and not lines[-1].strip():
        lines.pop()
    # 3. 计算所有行的最小左侧空格数，统一裁剪左边距
    min_left_pad = min(len(line) - len(line.lstrip()) for line in lines)
    # 输出最终美化后的图像
    for line in lines:
        print(line[min_left_pad:])


# ========== 主执行逻辑 ==========
if __name__ == '__main__':
    # 1. 从PNG中提取隐藏的十六进制k值
    hex_k = extract_hex_from_png('self_portrait.png')
    # 2. 十六进制转十进制大整数
    k = int(hex_k, 16)
    # 3. 计算位图对应的整数 n = floor(k / 17)
    n = k // 17
    # 4. 渲染并输出flag字符画
    render_tupper(n)
```

加入16进制参数

```python
hex_str = "d0409d4050c0264021bc000003da026c8136409b2041e000000cc0099004c80264021bc000003300264013200990086f00000217800220011000882178000004400220021bc088004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
WIDTH, HEIGHT = 107, 17  # 修正为标准107像素宽度

def render_tupper(n):
    lines = []
    for v in range(HEIGHT - 1, -1, -1):
        row = ''
        for x in range(WIDTH):
            bit = (n >> (17 * x + v)) & 1
            row += '█' if bit else ' '
        lines.append(row.rstrip())
    
    # 裁剪上下空白
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    
    # 裁剪左侧统一空白
    min_left = min(len(line) - len(line.lstrip()) for line in lines)
    result = []
    for line in lines:
        result.append(line[min_left:])
    return result

k = int(hex_str, 16)
n = k // 17
output = render_tupper(n)
for line in output:
    print(line)
```

![image-20261025231120022](/pwn-notes/images/notes/image-20261025231120022.png)

# Cyberpunk

居然是音频题吗

![image-20261025231808940](/pwn-notes/images/notes/image-20261025231808940.png)

还有图像还有压缩包

图像是

## LSB

![image-20261025232934203](/pwn-notes/images/notes/image-20261025232934203.png)

HERS ECRET

也就是只需要下面三个都是000就可以喽

然后是音频：

居然还有这·content

中是什么格鲁吉亚密码啥的

![image-20261026214450430](/pwn-notes/images/notes/image-20261026214450430.png)

KemahuKigkiiVixfxxkHvhipueusiRfhRlvx

![image-20261026220441648](/pwn-notes/images/notes/image-20261026220441648.png)

解密

DavidsTenderDevotedDependableAndPure

![image-20261026220757552](/pwn-notes/images/notes/image-20261026220757552.png)

f﻿‎‌﻿‏‍‍﻿‌﻿‎‍﻿﻿‍‍﻿‍﻿‍‌﻿‍‏﻿﻿‏﻿‌‏﻿‍‌‍﻿‌﻿‌﻿﻿‎‏﻿‌‎﻿‌‏﻿‍‏‍﻿‍﻿‎‏﻿‍‎﻿‏‎﻿‎‎﻿‎‏﻿‏﻿﻿‎‏‏‎‎‎lag是‘iamonthemoon’ 的md5

128个字符

隐藏的零宽字符

![image-20261026220932896](/pwn-notes/images/notes/image-20261026220932896.png)

# 碎境之章

我去，有点难

# 星辰科技

1.![image-20261028190948446](/pwn-notes/images/notes/image-20261028190948446.png)

查看网页源代码

![image-20261028191142083](/pwn-notes/images/notes/image-20261028191142083.png)

2.攻击时间

![image-20261028191510762](/pwn-notes/images/notes/image-20261028191510762.png)

3.后台文件

![image-20261028191801029](/pwn-notes/images/notes/image-20261028191801029.png)

![image-20261028191833987](/pwn-notes/images/notes/image-20261028191833987.png)

# deploy

咋还有镜像，好像是取证

<!-- sync-hash: 3da29170c1c41ac27b4214edb26f749616ae964bd0e67b1d955ed8a0fd14045b -->
