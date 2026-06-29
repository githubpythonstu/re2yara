# RE2YARA API Reference

> 本文档详细说明 RE2YARA 转换器的内部 API 和代码结构。

---

## 目录

- [架构概览](#架构概览)
- [RE2YARAVersionOnlyConverter](#re2yaraversiononlyconverter)
- [YARATestSuite](#yaratestssuite)
- [数据结构和类型](#数据结构和类型)
- [正则转换管道](#正则转换管道)
- [配置选项](#配置选项)

---

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                     re2yara_version_only_converter.py           │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              RE2YARAVersionOnlyConverter                   │  │
│  │                                                           │  │
│  │  - extract_class_info()      AST 解析                     │  │
│  │  - _process_attribute()      属性处理                     │  │
│  │  - python_to_yara_regex()    正则转换（14 阶段）          │  │
│  │  - generate_yara_rule()      YARA 规则生成               │  │
│  │  - convert_file()            单文件转换                   │  │
│  │  - convert_all()             批量转换                     │  │
│  │  - generate_regex_difference_report()  报告生成          │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              YARATestSuite                                 │  │
│  │                                                           │  │
│  │  - create_test_files()          创建测试样本              │  │
│  │  - test_yara_syntax()           语法验证                  │  │
│  │  - test_yara_functionality()    功能测试                  │  │
│  │  - test_all_yara_rules()        全量测试                  │  │
│  │  - generate_test_report()       报告生成                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              main() 入口                                   │  │
│  │                                                           │  │
│  │  - parse_arguments()            参数解析                  │  │
│  │  - handle_conversion()          转换模式                  │  │
│  │  - handle_syntax_testing()      语法测试模式              │  │
│  │  - handle_functionality_testing()  功能测试模式           │  │
│  │  - handle_legacy_testing()      兼容旧模式                │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## RE2YARAVersionOnlyConverter

### 类定义

```python
class RE2YARAVersionOnlyConverter:
    """Converts only Python VERSION_PATTERNS to YARA rules with focused traceability"""
    
    def __init__(self, source_dir: str, target_dir: str):
        self.source_dir = Path(source_dir)
        self.target_dir = Path(target_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.conversion_stats = {...}
```

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `source_dir` | `Path` | 源 Python 文件目录 |
| `target_dir` | `Path` | YARA 规则输出目录 |
| `conversion_stats` | `Dict` | 转换统计信息 |

### conversion_stats 结构

```python
{
    'total_files': int,              # 处理的文件总数
    'converted_files': int,          # 成功转换数
    'failed_files': int,             # 失败数
    'regex_difference_notes': List,  # 正则差异记录
    'conversion_time': str           # 转换时间戳 (ISO format)
}
```

---

### 方法详解

#### extract_class_info(file_path, args=None) -> Optional[Dict]

AST 解析 Python 文件，提取 Checker 类信息。

**参数：**
- `file_path: Path` — Python 文件路径
- `args` — 命令行参数（可选，用于 verbose 调试）

**返回：**
```python
{
    'name': str,                # 类名（如 'CurlChecker'）
    'filename': str,            # 文件名（如 'curl'）
    'version_patterns': List[str],  # VERSION_PATTERNS 列表
    'vendor_product': List[Tuple[str, str]]  # VENDOR_PRODUCT 列表
}
```

**异常处理：**
- 没有找到 Checker 类 → 返回 None
- AST 解析失败 → 打印错误，返回 None

---

#### _process_attribute(attr_name, attr_value, class_info, args) -> None

处理单个 AST 属性节点。

**支持的属性：**
- `VERSION_PATTERNS` — 提取版本正则模式
- `VENDOR_PRODUCT` — 提取供应商-产品对

**AST 节点类型：**
- `ast.Assign` — 常规赋值（Python < 3.8）
- `ast.AnnAssign` — 带类型注解的赋值（Python >= 3.8）
- `ast.Constant` — 常量值（Python >= 3.8）
- `ast.Str` — 字符串值（Python < 3.8，已弃用）

---

#### python_to_yara_regex(python_regex, source_info=None) -> str

核心方法：将 Python 正则转换为 YARA 兼容正则。

**参数：**
- `python_regex: str` — Python 正则表达式
- `source_info: Dict` — 源信息（用于追踪）

**返回：**
- YARA 兼容的正则字符串

**14 阶段转换管道：**

```python
def python_to_yara_regex(self, python_regex, source_info=None):
    # 阶段 1: 移除 %s 占位符
    # 阶段 2: 修复空替代 (|pattern) → (^pattern)
    # 阶段 3: 转换 .*? → [^\x0A\x0D]*
    # 阶段 4: 优化 \- 在字符类中的位置
    # 阶段 5: 转换 (?:...) → (...)
    # 阶段 6: 修复开头的 \r?\n
    # 阶段 7: 转换 (?P<name>...) → (...)
    # 阶段 8: 移除条件组 (?(...)...)
    # 阶段 9: 移除环视 (?=...), (?!...), (?<=...), (?<!...)
    # 阶段 10: 转换占有量词 ++, *, ?+
    # 阶段 11: 转义正斜杠 / → \/
    # 阶段 12: 修复反转字符范围 [z-a] → [a-z]
    # 阶段 13: 平衡 [] 括号
    # 阶段 14: 最终验证和清理
```

---

#### generate_yara_rule(class_info) -> str

生成完整的 YARA 规则文本。

**参数：**
- `class_info: Dict` — extract_class_info() 的返回值

**返回：**
- 格式化的 YARA 规则字符串

**命名规则：**
```python
rule_name = f"{class_info['filename']}_version_only"
rule_name = rule_name.replace('.', '_').replace('-', '_').replace(' ', '_')
if rule_name[0].isdigit():
    rule_name = f"_{rule_name}"
```

---

#### convert_file(source_file, args=None) -> bool

转换单个 Python 文件。

**返回：**
- `True` — 转换成功
- `False` — 转换失败

**副作用：**
- 在 target_dir 创建 `.yara` 文件
- 更新 conversion_stats

---

#### convert_all(args=None) -> None

批量转换所有 Python 文件。

**流程：**
1. 扫描 source_dir 下所有 `.py` 文件
2. 排除 `__init__.py`
3. 逐个调用 convert_file()
4. 打印统计信息

---

#### generate_regex_difference_report() -> None

生成转换差异报告。

**输出文件：**
- `regex_difference_report.md` — 人类可读报告
- `regex_difference_trace.json` — 机器可读 JSON

---

## YARATestSuite

### 类定义

```python
class YARATestSuite:
    """Comprehensive testing suite for generated YARA rules"""
    
    def __init__(self, yara_binary_path: str, yarac_binary_path: str):
        self.yara_binary = Path(yara_binary_path)
        self.yarac_binary = Path(yarac_binary_path)
        self.test_results = {...}
```

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `yara_binary` | `Path` | YARA 扫描器路径 |
| `yarac_binary` | `Path` | YARA 编译器路径 |
| `test_results` | `Dict` | 测试结果存储 |

### test_results 结构

```python
{
    'syntax_tests': List[Dict],      # 语法测试结果
    'functional_tests': List[Dict],  # 功能测试结果
    'performance_tests': List[Dict], # 性能测试结果
    'summary': {
        'total_rules': int,
        'syntax_passed': int,
        'syntax_failed': int,
        'functional_passed': int,
        'functional_failed': int,
        'test_timestamp': str
    }
}
```

---

### 方法详解

#### create_test_files() -> Dict[str, Path]

创建测试样本文件。

**返回：**
```python
{
    'curl_test.txt': Path('test_generated_files/curl_test.txt'),
    'openssl_test.txt': Path('test_generated_files/openssl_test.txt'),
    'nginx_test.txt': Path('test_generated_files/nginx_test.txt'),
    'apache_test.txt': Path('test_generated_files/apache_test.txt'),
    'general_versions.txt': Path('test_generated_files/general_versions.txt')
}
```

---

#### test_yara_syntax(yara_file) -> Dict

测试单个 YARA 规则的语法。

**返回：**
```python
{
    'rule_file': str,           # 规则文件路径
    'syntax_valid': bool,       # 语法是否有效
    'error_message': str,       # 错误信息（如有）
    'compilation_time': float,  # 编译耗时（秒）
    'rule_size': int            # 规则文件大小（字节）
}
```

**实现：**
```python
result = subprocess.run(
    [str(self.yarac_binary), str(yara_file), str(compiled_output)],
    capture_output=True, text=True, timeout=30
)
```

---

#### test_yara_functionality(yara_file, test_files) -> Dict

测试 YARA 规则的功能性。

**返回：**
```python
{
    'rule_file': str,
    'matches': Dict[str, Dict],     # 每个测试文件的匹配结果
    'total_scans': int,             # 总扫描次数
    'successful_scans': int,        # 成功扫描次数
    'scan_time': float,             # 总扫描时间
    'errors': List[str]             # 错误列表
}
```

---

#### test_all_yara_rules(yara_directory) -> Dict

全量测试指定目录下的所有 YARA 规则。

**流程：**
1. 创建测试文件
2. Phase 1: 语法验证（所有规则）
3. Phase 2: 功能测试（仅通过语法的规则）
4. 返回完整结果

---

#### test_syntax_only(yara_file) -> Dict

测试单个文件的语法（独立方法）。

#### test_syntax_all(yara_directory) -> Dict

测试目录下所有文件的语法。

#### test_functionality_only(yara_file) -> Dict

测试单个文件的功能（独立方法）。

#### test_functionality_all(yara_directory) -> Dict

测试目录下所有文件的功能。

#### test_single_yara_file(yara_file) -> Dict

综合测试单个文件（语法 + 功能）。

---

#### generate_test_report(report_file) -> None

生成综合测试报告（Markdown 格式）。

#### generate_syntax_report(report_file) -> None

生成语法测试报告。

#### generate_functionality_report(report_file) -> None

生成功能测试报告。

---

## 数据结构和类型

### Checker 类（Python 输入）

```python
class SomeSoftwareChecker(Checker):
    CONTAINS_PATTERNS: List[str] = [r"pattern1", r"pattern2"]
    FILENAME_PATTERNS: List[str] = [r"filename_regex"]
    VERSION_PATTERNS: List[str] = [r"version_regex"]
    VENDOR_PRODUCT: List[Tuple[str, str]] = [("vendor", "product")]
```

### 生成的 YARA 规则

```yara
rule software_name_version_only
{
    meta:
        software_name = "Software Name"
        open_source = true
        website = "Generated from Python VERSION_PATTERNS only"
        description = "Version detection rule for Software Name"
        generated_from = "source_python_re/software.py"
        conversion_mode = "version_only"
        vendor_product = "vendor:product"
    strings:
        $version0 = /pattern/ nocase ascii wide
    condition:
        any of them
}
```

### 正则差异记录

```python
{
    'source_file': "curl.py",
    'pattern_type': "VERSION_PATTERNS",
    'pattern_index': 0,
    'original_pattern': r"\r?\ncurl[ -]([0-9]+\.[0-9]+)",
    'converted_pattern': r"(^|\r?\n)curl[ -]([0-9]+\.[0-9]+)",
    'differences_triggered': ["newline_to_group_anchor_fix"],
    'conversion_timestamp': "2026-06-29T10:00:00"
}
```

---

## 正则转换管道

### 完整转换表

| 阶段 | Python 特性 | YARA 转换 | 示例 |
|------|------------|-----------|------|
| 1 | `%s` 占位符 | 移除 | `"%s ver"` → `"ver"` |
| 2 | 空替代 | 添加锚点 | `(\|pattern)` → `(^pattern)` |
| 3 | `.*?` 懒惰 | 字符类 | `.*?` → `[^\x0A\x0D]*` |
| 4 | `\-` 在字符类 | 移到最后 | `[a\-z]` → `[az-]` |
| 5 | `(?:...)` 非捕获 | 捕获组 | `(?:...)` → `(...)` |
| 6 | 开头 `\r?\n` | 锚点组 | `\r?\n` → `(^\|\r?\n)` |
| 7 | `(?P<name>...)` | 捕获组 | `(?P<v>...)` → `(...)` |
| 8 | 条件组 | 移除 | `(?(...)...)` → `` |
| 9 | 环视 | 移除 | `(?=...)` → `` |
| 10 | 占有量词 | 标准量词 | `++` → `+` |
| 11 | `/` 正斜杠 | 转义 | `/` → `\/` |
| 12 | 反转范围 | 修复 | `[z-a]` → `[a-z]` |
| 13 | 不平衡括号 | 平衡 | `[abc` → `[abc]` |
| 14 | 最终验证 | 清理 | 移除无效转义 |

### 有效 YARA 转义字符

```python
valid_yara_escapes = {
    'r', 'n', 't', 'f', 'v', 'a', 'b',      # 基本转义
    'd', 'D', 's', 'S', 'w', 'W',           # 字符类
    'x', 'u', 'U',                           # 十六进制/Unicode
    'l', 'L', 'h', 'H',                      # 大小写
    'R', 'V',                                 # 行/垂直空白
    'k', 'K',                                 # 命名组引用
    'p', 'P', 'g', 'G',                      # 命名组
    'A', 'Z', 'B', 'E', 'N', 'O', 'Q',      # 锚点/断言
    'C', 'I', 'J'                             # 调用out
}
```

---

## 配置选项

### 命令行参数

```bash
py re2yara_version_only_converter.py [COMMAND] [OPTIONS]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--source-dir, -s` | `source_python_re` | 源 Python 文件目录 |
| `--target-dir, -t` | `target_yara_version_only` | YARA 规则输出目录 |
| `--yara-binary` | `bin/yara64.exe` | YARA 扫描器路径 |
| `--yarac-binary` | `bin/yarac64.exe` | YARA 编译器路径 |
| `--verbose, -v` | `False` | 启用详细输出 |
| `--test` | `None` | 旧版综合测试（已弃用） |

### 子命令

| 子命令 | 说明 |
|--------|------|
| `test-syntax [file]` | 测试 YARA 语法 |
| `test-functionality [file]` | 测试 YARA 功能 |

### 环境变量

| 变量 | 说明 |
|------|------|
| `PATH` | 需要包含 Python 3.8+ |

---

## 报告文件

| 文件 | 格式 | 内容 |
|------|------|------|
| `regex_difference_report.md` | Markdown | 转换差异摘要 |
| `regex_difference_trace.json` | JSON | 完整转换追踪 |
| `yara_syntax_test_report.md` | Markdown | 语法测试结果 |
| `yara_functionality_test_report.md` | Markdown | 功能测试结果 |
| `yara_comprehensive_test_report.md` | Markdown | 综合测试结果（旧版） |

---

## 使用示例

### 作为 Python 模块

```python
from re2yara_version_only_converter import RE2YARAVersionOnlyConverter

converter = RE2YARAVersionOnlyConverter("checkers/", "output/")
converter.convert_all()
converter.generate_regex_difference_report()
```

### 作为测试框架

```python
from re2yara_version_only_converter import YARATestSuite

suite = YARATestSuite("bin/yara64.exe", "bin/yarac64.exe")
results = suite.test_all_yara_rules(Path("target_yara_version_only/"))
suite.generate_test_report(Path("test_report.md"))
```

---

*文档版本: 1.0 | 更新日期: 2026-06-29*
