# RE2YARA 开发指南

> 面向贡献者和开发者的详细指南。

---

## 目录

- [开发环境设置](#开发环境设置)
- [项目架构](#项目架构)
- [添加新的 Checker](#添加新的-checker)
- [修改转换管道](#修改转换管道)
- [运行测试](#运行测试)
- [代码规范](#代码规范)
- [提交指南](#提交指南)

---

## 开发环境设置

### 系统要求

| 要求 | 最低版本 | 推荐版本 |
|------|---------|---------|
| Python | 3.8 | 3.11+ |
| YARA | 4.2.3 | 4.3+ |
| Git | 2.30 | 2.40+ |
| 操作系统 | Windows 10 / Linux / macOS | - |

### 安装步骤

```bash
# 1. 克隆仓库
git clone https://github.com/githubpythonstu/re2yara.git
cd re2yara

# 2. 验证 Python 版本
py --version  # 需要 3.8+

# 3. 验证 YARA 二进制
ls bin/yara64.exe
ls bin/yarac64.exe

# 4. 运行测试
py re2yara_version_only_converter.py --help
```

### 开发工具推荐

| 工具 | 用途 | 配置 |
|------|------|------|
| VS Code | 代码编辑 | Python 扩展 |
| Python Extension | 语法检查、调试 | Pylint / mypy |
| Git Graph | 可视化分支 | VS Code 扩展 |

---

## 项目架构

### 核心模块

```
re2yara/
├── re2yara_version_only_converter.py   # 主转换器（2054 行）
│   ├── RE2YARAVersionOnlyConverter      # 转换引擎
│   ├── YARATestSuite                    # 测试框架
│   └── main()                           # CLI 入口
│
├── file_filter_dedup.py                 # 文件过滤去重
│   └── FileFilterDeduplicator           # 过滤引擎
│
├── checkers/                            # Python checker 源文件
│   ├── __init__.py                      # Checker 基类
│   └── <software>.py                    # 各个软件检测器
│
├── signatures/                          # YARA 参考签名
│   ├── 00_meta_filter.yara              # 元过滤器
│   └── <category>.yara                  # 分类规则
│
└── bin/                                 # YARA 二进制
    ├── yara64.exe                       # 扫描器
    └── yarac64.exe                      # 编译器
```

### 数据流

```
输入                              处理                           输出
─────                              ────                           ────
checkers/*.py  ──▶  AST 解析  ──▶  VERSION_PATTERNS
                                        │
                                        ▼
                              14 阶段正则转换
                                        │
                                        ▼
                              YARA 规则生成  ──▶  target_yara_version_only/*.yara
                                        │
                                        ▼
                              差异报告生成  ──▶  regex_difference_report.md
```

---

## 添加新的 Checker

### 步骤 1：创建 Checker 文件

在 `checkers/` 目录下创建 `<software>.py`：

```python
# Copyright (C) 2024
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for <Software Name>

References:
https://example.com/security
"""

from cve_bin_tool.checkers import Checker


class <SoftwareName>Checker(Checker):
    CONTAINS_PATTERNS = [
        r"unique string found in binary",
        r"another identifying pattern",
    ]
    FILENAME_PATTERNS = [
        r"software_name",
    ]
    VERSION_PATTERNS = [
        r"software_name[ /]([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("vendor_name", "software_name")]
```

### 步骤 2：验证 Checker 格式

```python
# 检查清单
✅ 类名以 Checker 结尾
✅ 继承自 Checker
✅ VENDOR_PRODUCT 全部小写
✅ VERSION_PATTERNS 使用原始字符串 r"..."
✅ 至少有一个 VERSION_PATTERN
```

### 步骤 3：运行转换

```bash
# 转换单个文件
py re2yara_version_only_converter.py --source-dir checkers/ --target-dir output/

# 检查生成的 YARA 规则
cat output/<software>_version_only.yara
```

### 步骤 4：测试规则

```bash
# 语法测试
py re2yara_version_only_converter.py test-syntax output/<software>_version_only.yara

# 功能测试
py re2yara_version_only_converter.py test-functionality output/<software>_version_only.yara

# 手动测试
echo "software_name 1.2.3" > test.txt
bin/yara64.exe output/<software>_version_only.yara test.txt
```

### 步骤 5：提交 PR

```bash
git add checkers/<software>.py
git commit -m "feat: add <software> checker"
git push origin feat/add-<software>-checker
gh pr create --title "feat: add <software> checker" --body "..."
```

---

## 修改转换管道

### 添加新的转换阶段

在 `python_to_yara_regex()` 方法中添加：

```python
def python_to_yara_regex(self, python_regex, source_info=None):
    # ... 现有阶段 ...
    
    # 阶段 N: 你的新转换
    # 描述：转换 X 为 Y
    original = yara_regex
    yara_regex = re.sub(r'pattern', r'replacement', yara_regex)
    if original != yara_regex:
        differences_triggered.append(f"your_new_transformation")
    
    # ... 后续阶段 ...
```

### 测试新转换

```python
# 创建测试用例
test_cases = [
    (r'input_pattern', r'expected_output'),
    (r'another_input', r'another_expected'),
]

# 验证
for input_pattern, expected in test_cases:
    result = converter.python_to_yara_regex(input_pattern)
    assert result == expected, f"Failed: {input_pattern} → {result} (expected {expected})"
```

---

## 运行测试

### 语法测试

```bash
# 测试所有规则
py re2yara_version_only_converter.py test-syntax

# 测试单个规则
py re2yara_version_only_converter.py test-syntax target_yara_version_only/curl_version_only.yara
```

### 功能测试

```bash
# 测试所有规则
py re2yara_version_only_converter.py test-functionality

# 测试单个规则
py re2yara_version_only_converter.py test-functionality target_yara_version_only/curl_version_only.yara
```

### 手动测试

```bash
# 创建测试文件
echo "curl 7.68.0" > test_curl.txt
echo "OpenSSL 1.1.1f" > test_openssl.txt

# 运行 YARA 扫描
bin/yara64.exe target_yara_version_only/curl_version_only.yara test_curl.txt
bin/yara64.exe target_yara_version_only/openssl_version_only.yara test_openssl.txt

# 递归扫描目录
bin/yara64.exe -r target_yara_version_only/ /path/to/scan/
```

### 性能测试

```bash
# 测量转换时间
time py re2yara_version_only_converter.py

# 测量扫描时间
time bin/yara64.exe -r target_yara_version_only/ /path/to/scan/
```

---

## 代码规范

### Python 风格

```python
# 遵循 PEP 8
# 最大行宽: 100 字符
# 缩进: 4 空格
# 引号: 双引号（字符串），原始字符串（正则）

# 好的风格
def python_to_yara_regex(self, python_regex: str, source_info: Dict = None) -> str:
    """Convert Python regex to YARA format."""
    if not python_regex:
        return ""
    # ... implementation ...

# 差的风格
def python_to_yara_regex(self,python_regex,source_info=None):
    if not python_regex:return ""
    # ... implementation ...
```

### 命名约定

| 类型 | 约定 | 示例 |
|------|------|------|
| 类名 | PascalCase | `CurlChecker` |
| 函数名 | snake_case | `extract_class_info` |
| 常量 | UPPER_SNAKE | `VERSION_PATTERNS` |
| 私有方法 | _leading_underscore | `_process_attribute` |
| 变量 | snake_case | `yara_regex` |

### 文档字符串

```python
def extract_class_info(self, file_path: Path, args=None) -> Optional[Dict]:
    """
    Extract VERSION_PATTERNS from Python file.
    
    Args:
        file_path: Path to the Python checker file.
        args: Command line arguments for debugging.
    
    Returns:
        Dictionary with extracted info, or None if parsing fails.
    
    Example:
        >>> converter.extract_class_info(Path("checkers/curl.py"))
        {'name': 'CurlChecker', 'filename': 'curl', ...}
    """
```

### 类型注解

```python
from typing import List, Dict, Tuple, Optional

# 始终使用类型注解
def convert_file(self, source_file: Path, args: Optional[Namespace] = None) -> bool:
    class_info: Optional[Dict] = self.extract_class_info(source_file, args)
    patterns: List[str] = class_info.get('version_patterns', [])
```

---

## 提交指南

### Commit Message 格式

```
<type>: <subject>

<body>

<footer>
```

| 类型 | 说明 | 示例 |
|------|------|------|
| `feat` | 新功能 | `feat: add Foobar checker` |
| `fix` | 修复 bug | `fix: regex conversion for edge case` |
| `docs` | 文档更新 | `docs: add API reference` |
| `test` | 测试相关 | `test: add unit tests for converter` |
| `refactor` | 重构 | `refactor: simplify regex pipeline` |
| `perf` | 性能优化 | `perf: reduce memory usage` |
| `chore` | 杂项 | `chore: update .gitignore` |

### 示例

```bash
# 好的 commit
git commit -m "feat: add Foobar checker

- Add checker definition for Foobar software
- Include 3 version patterns for different formats
- All tests pass

Closes #123"

# 差的 commit
git commit -m "update"
```

### PR 流程

```bash
# 1. 创建功能分支
git checkout -b feat/add-foobar-checker

# 2. 开发和提交
git add checkers/foobar.py
git commit -m "feat: add Foobar checker"

# 3. 推送分支
git push origin feat/add-foobar-checker

# 4. 创建 PR
gh pr create \
  --title "feat: add Foobar checker" \
  --body "## Summary
  - Add Foobar checker
  - Support version patterns X, Y, Z
  
  Closes #123" \
  --label "enhancement"

# 5. 等待 Review
# 6. 根据反馈修改
# 7. Merge
```

---

## 常见问题

### Q: 转换后的规则不匹配？

1. 检查 `regex_difference_report.md` 查看转换差异
2. 确认是否有不支持的特性被移除
3. 手动调整 YARA 规则

### Q: 如何调试 AST 解析？

```bash
# 使用 verbose 模式
py re2yara_version_only_converter.py -v
```

### Q: 如何添加新的测试样本？

在 `YARATestSuite.create_test_files()` 中添加：

```python
test_files['my_test.txt'] = [
    "mysoftware 1.0.0\n",
    "mysoftware 2.1.3\n",
]
```

---

*文档版本: 1.0 | 更新日期: 2026-06-29*
