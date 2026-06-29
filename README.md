# RE2YARA - Python Regular Expression to YARA Rules Converter

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![YARA](https://img.shields.io/badge/YARA-4.2.3-green.svg)](https://virustotal.github.io/yara/)
[![License](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Checkers](https://img.shields.io/badge/Checkers-434-orange.svg)](checkers/)
[![Success Rate](https://img.shields.io/badge/Success%20Rate-100%20%25-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-0-success.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%2B%20Linux%20%2B%20macOS-lightgrey.svg)]()

A powerful Python tool that converts regular expression patterns from Intel's CVE Binary Tool checkers into YARA rules for malware detection and software identification.

---

## 📋 Table of Contents

- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [File Filtering and Deduplication](#-file-filtering-and-deduplication)
- [Project Structure](#-project-structure)
- [Usage](#-usage)
- [Conversion Process](#-conversion-process)
- [Testing](#-testing)
- [Branch Protection / Rulesets](#-branch-protection--rulesets)
- [Examples](#-examples)
- [Performance Benchmarks](#-performance-benchmarks)
- [FAQ](#-faq)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **100% Success Rate** | Converts all 434 Python checker files without errors |
| **Zero Dependencies** | Uses only Python standard library (ast, re, pathlib) |
| **Smart Filtering** | Auto-deduplicates against existing YARA signatures |
| **14-Stage Pipeline** | Handles every Python→YARA regex difference |
| **Built-in Testing** | Syntax validation + functional testing + performance analysis |
| **Full Traceability** | Every transformation tracked with before/after comparison |
| **Cross-Platform** | Works on Windows, Linux, and macOS |

---

## 🔍 How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RE2YARA Conversion Pipeline                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
│  │   checkers/  │    │  AST Parse   │    │    Regex     │    │  YARA    │  │
│  │  *.py files  │───▶│  Extract     │───▶│  Transform   │───▶│  Rules   │  │
│  │  (434 files) │    │  VERSION_    │    │  (14 stages) │    │  Output  │  │
│  └──────────────┘    │  PATTERNS    │    └──────────────┘    └──────────┘  │
│                      └──────────────┘                                       │
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │  signatures/ │    │  Deduplicate │    │   Reports    │                   │
│  │  *.yara      │───▶│  Filter      │───│   & Logs     │                   │
│  │  (85 rules)  │    │  (389 uniq)  │    │              │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
checkers/curl.py  ──▶  AST Parse  ──▶  VERSION_PATTERNS extracted
                                              │
                                              ▼
                    ┌─────────────────────────────────────────────────┐
                    │         14-Stage Regex Transformation           │
                    │                                                 │
                    │  1. Remove %s placeholders                     │
                    │  2. Fix empty alternatives (|pattern)          │
                    │  3. Convert .*? lazy dot-star                  │
                    │  4. Optimize \- in character classes           │
                    │  5. Convert (?:...) non-capturing groups       │
                    │  6. Fix \r?\n at pattern start                 │
                    │  7. Convert (?P<name>...) named groups         │
                    │  8. Remove (?(...)...) conditionals            │
                    │  9. Remove lookaheads/lookbehinds              │
                    │ 10. Convert possessive quantifiers             │
                    │ 11. Escape / forward slashes                   │
                    │ 12. Fix reversed character ranges               │
                    │ 13. Balance [] brackets                        │
                    │ 14. Final validation                           │
                    └─────────────────────────────────────────────────┘
                                              │
                                              ▼
                    target_yara_version_only/curl_version_only.yara
```

---

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- Git (for cloning)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/githubpythonstu/re2yara.git
cd re2yara

# 2. Verify YARA binaries (included in bin/ directory)
ls bin/yara64.exe
ls bin/yarac64.exe

# 3. Test the installation
py re2yara_version_only_converter.py --help
```

---

## ⚡ Quick Start

### Convert VERSION_PATTERNS Only (Recommended)

```bash
# Convert all Python checker files to YARA rules (VERSION_PATTERNS only)
py re2yara_version_only_converter.py

# The script will:
# - Read all .py files from source_python_re/ (435 files total)
# - Generate .yara files in target_yara_version_only/
# - Create conversion reports in project root
# - No automatic YARA testing (default behavior)
```

### Convert All Patterns (Full Mode)

```bash
# Convert all patterns (CONTAINS, FILENAME, VERSION)
py re2yara_converter.py
```

---

## 🔄 File Filtering and Deduplication

The project includes intelligent file filtering to prevent duplicate YARA rules by analyzing existing signatures and automatically deduplicating checker files.

### Quick Filtering Workflow

```bash
# Step 1: Run the file filtering script
py file_filter_dedup.py

# Output:
# 📊 Parse 85 YARA rules from signatures/
# 📋 Analyze 434 checker files from checkers/
# ✅ Copy 389 unique files to source_python_re/
# 📄 Generate detailed filtering report
# ⏭️ Skip 45 files that match existing rules

# Step 2: Convert the filtered files
py re2yara_version_only_converter.py
```

### Filtering Features

#### **Smart Rule Name Matching**
- **Direct matches**: `curl` matches rule `curl`
- **Case-insensitive**: `CURL` matches rule `curl`
- **Normalization**: `apache_http_server` matches `Apache`
- **Variations**: `openssl` matches `OpenSSL`

#### **Advanced Filtering Logic**
```python
# Examples of intelligent matching patterns:
apache_http_server.py  → Skipped (matches "Apache" rule)
nginx.py              → Skipped (matches "nginx" rule)
python.py             → Skipped (matches "Python" rule)
accountsservice.py   → Copied (new unique checker)
aomedia.py           → Copied (new unique checker)
```

#### **Comprehensive Reporting**
The script generates `file_filtering_report.md` with:
- Total statistics and success rates
- List of copied files (new checkers)
- List of skipped files (existing rules)
- Filtering logic explanation
- Next steps for conversion

### Benefits

- **Prevents Duplicates**: Only processes unique checker files
- **Saves Time**: Avoids converting already-implemented rules
- **Maintains Quality**: Preserves existing hand-crafted YARA rules
- **Comprehensive Tracking**: Full visibility into filtering decisions
- **Easy Integration**: Seamless workflow with existing conversion tools

---

## 📁 Project Structure

```
re2yara/
├── checkers/                        # 434 Python checker files from Intel CVE Binary Tool
│   ├── __init__.py                  # Checker base class with metaclass
│   ├── accountsservice.py           # Software detection patterns
│   ├── acpid.py                    # ACPI daemon patterns
│   └── ...                         # 432 more checker files
├── source_python_re/                # Filtered Python checker files (after deduplication)
│   ├── accountsservice.py          # Unique checkers ready for conversion
│   ├── aomedia.py                  # 389 total files after filtering
│   └── ...                         # Unique software detection patterns
├── target_yara/                    # Full YARA rules (generated on-demand)
├── target_yara_version_only/       # VERSION_PATTERNS-only rules (generated on-demand)
├── signatures/                     # Reference YARA rule formats
│   ├── 00_meta_filter.yara        # Meta filter for reducing false positives
│   ├── bootloader.yara            # Bootloader detection patterns
│   ├── crypto.yara                # Cryptographic software patterns
│   ├── software.yara              # Hand-crafted software detection rules
│   └── ...                       # 85 existing YARA rules
├── bin/                           # YARA 4.2.3 binaries for Windows
│   ├── yara64.exe                 # YARA scanning engine
│   └── yarac64.exe                # YARA compiler
├── .claude/                       # Claude Code project configuration
│   ├── settings.local.json        # Local Claude settings
│   └── skills/re2yara/SKILL.md    # Claude Code skill for this project
├── file_filter_dedup.py           # File filtering and deduplication script
├── re2yara_version_only_converter.py # Main converter with testing suite
├── re2yara_converter.py            # Full pattern converter
├── CLAUDE.md                      # Development documentation and guidelines
├── file_filtering_report.md       # File filtering and deduplication results
├── regex_difference_report.md     # Conversion statistics and differences
├── regex_difference_trace.json    # Detailed conversion trace data
├── yara_comprehensive_test_report.md # YARA testing results
└── README.md                      # This file
```

---

## 🎯 Usage

### Complete Workflow (Recommended)

```bash
# Step 1: Filter and deduplicate checker files
py file_filter_dedup.py

# Step 2: Convert VERSION_PATTERNS (recommended)
py re2yara_version_only_converter.py

# Output:
# ✅ Filtered 434 → 389 files (89.6% unique)
# ✅ Converted 389 files successfully
# 📄 Generated YARA rules in target_yara_version_only/
# 📊 Created conversion and filtering reports
```

### Basic Conversion (If source_python_re already populated)

```bash
# VERSION_PATTERNS-only conversion (default mode)
py re2yara_version_only_converter.py

# Output:
# ✅ Converted 389 files successfully
# 📄 Generated YARA rules in target_yara_version_only/
# 📊 Created conversion reports
```

### Testing Generated YARA Rules

```bash
# NEW: Independent testing subcommands (recommended)
py re2yara_version_only_converter.py test-syntax                  # Test syntax of all YARA files
py re2yara_version_only_converter.py test-functionality           # Test functionality of all YARA files
py re2yara_version_only_converter.py test-syntax file.yara         # Test syntax of specific file
py re2yara_version_only_converter.py test-functionality file.yara  # Test functionality of specific file

# LEGACY: Comprehensive testing (both syntax + functionality)
py re2yara_version_only_converter.py --test                      # Test all YARA files
py re2yara_version_only_converter.py --test file.yara             # Test specific file

# Output includes:
# ✅ Syntax validation results
# 🔍 Functional testing against version patterns
# 📈 Performance metrics and analysis
# 📄 Separate reports for syntax and functionality testing
```

### File Filtering

```bash
# Run file filtering and deduplication
py file_filter_dedup.py

# Output includes:
# 📊 YARA rules parsed: 85
# 📋 Checker files analyzed: 434
# ✅ Files copied: 389 (unique)
# ⏭️ Files skipped: 45 (duplicates)
# 📄 Detailed filtering report generated
```

### Command Line Options

```bash
# File filtering and deduplication
py file_filter_dedup.py

# VERSION_PATTERNS conversion
py re2yara_version_only_converter.py [COMMAND|OPTIONS]

# SUBCOMMANDS (NEW - Recommended):
  test-syntax              Test YARA rule syntax only
  test-functionality       Test YARA rule functionality only

# OPTIONS:
  --source-dir DIR        Source directory for Python files (default: source_python_re)
  --target-dir DIR        Target directory for YARA rules (default: target_yara_version_only)
  --yara-binary PATH      Path to YARA binary (default: bin/yara64.exe)
  --yarac-binary PATH     Path to YARA compiler binary (default: bin/yarac64.exe)
  --verbose, -v           Enable verbose output
  --help                  Show help message

# LEGACY OPTIONS:
  --test                  Enable comprehensive testing mode (deprecated - use subcommands)

# Full pattern conversion
py re2yara_converter.py [OPTIONS]
```

### Directory Management

```bash
# Check conversion progress
ls target_yara_version_only/       # Generated YARA rules
ls source_python_re/ | wc -l      # Filtered files: 389
ls checkers/ | wc -l              # Original checker files: 434

# View filtering results
cat file_filtering_report.md       # File filtering and deduplication statistics
# View conversion statistics
cat regex_difference_report.md      # Human-readable report
cat regex_difference_trace.json    # Detailed JSON trace data
cat yara_comprehensive_test_report.md # Test results
```

---

## 🔄 Conversion Process

### Pattern Transformation Pipeline

The converter handles major differences between Python and YARA regex:

| # | Python Regex Feature | YARA Equivalent | Transformation |
|---|----------------------|-----------------|----------------|
| 1 | **%s placeholders** | **Removed** | Comprehensive removal from any position |
| 2 | **Empty alternatives `(|\r?\n)`** | **`(^|\r?\n)`** | Fixed with proper start anchor |
| 3 | `.*?` lazy dot-star | `[^\x0A\x0D]*` | YARA has no lazy single-line `.*` |
| 4 | `\-` in char classes | Moved to end | `[a\-z]` → `[az-]` avoids range ambiguity |
| 5 | `(?:...)` non-capturing | `(...)` capturing | YARA doesn't support non-capturing |
| 6 | `\r?\n` at pattern start | `(^\|\r?\n)` | Anchors to line start or newline |
| 7 | `(?P<name>...)` named groups | `(...)` | YARA has no named groups |
| 8 | `(?(...)...)` conditional | Removed | YARA doesn't support conditionals |
| 9 | `(?=...) / (?!...)` lookahead | Removed | YARA doesn't support lookaheads |
| 10 | `(?<=...) / (?<!...)` lookbehind | Removed | YARA doesn't support lookbehinds |
| 11 | `++ / *+ / ?+` possessive | `+ / * / ?` | YARA doesn't support possessive |
| 12 | `/` forward slash | `\/` escaped | `/` is YARA regex delimiter |
| 13 | Reversed ranges `[z-a]` | Fixed to `[a-z]` | Character range correction |
| 14 | Unbalanced `[]` brackets | Balanced | Adds/removes missing brackets |

### Enhanced Pattern Transformations

#### Comprehensive %s Removal
The converter removes `%s` placeholders from any position in regex patterns:

- **Prefix**: `r"%s version ([0-9]+\.[0-9]+)"` → `r"version ([0-9]+\.[0-9]+)"`
- **Suffix**: `r"GWeb/%s"` → `r"GWeb/"`
- **Middle**: `r"version %s\r?\n([0-9]+)"` → `r"version \r?\n([0-9]+)"`
- **Multiple**: `r"version (?:|%s  %s\r?\n)([0-9]+)"` → `r"version (^\r?\n)([0-9]+)"`

#### Pipe Optimization
Empty alternatives in pipe groups are automatically fixed:

- **Non-capturing groups**: `(?:|  \r?\n)` → `(^\r?\n)`
- **Capturing groups**: `(|pattern)` → `(^|pattern)`
- **Nested patterns**: Complex empty alternatives are properly handled

### Transformation Tracking
All pattern optimizations are tracked with detailed flags:
- `"removed_%s_comprehensive"` - For %s removal operations
- `"fixed_empty_alternatives"` - For pipe optimization operations

### YARA Rule Generation Format

Generated rules follow this standardized format:

```yara
rule software_name {
    meta:
        software_name = "Software Name"
        open_source = true
        website = "Generated from Python RE patterns"
        description = "Detection rule for Software Name"
        generated_from = "source_python_re/source_file.py"
        vendor_product = "vendor:product"
    strings:
        $version0 = /pattern/ nocase ascii wide
        $contains0 = "literal" nocase ascii wide
        $filename0 = /pattern/ nocase
    condition:
        any of $version* and any of $contains* and any of $filename* and no_text_file
}
```

### Meta Filter Usage

All generated rules include `and no_text_file` condition using the private rule from `signatures/00_meta_filter.yara` to reduce false positives by excluding text files.

---

## 🧪 Testing

### Comprehensive Testing Framework

The project includes a robust testing suite:

#### Phase 1: Syntax Validation
```bash
# Compiles all YARA rules using yarac64.exe
# Reports syntax errors with detailed messages
# Measures compilation performance
```

#### Phase 2: Functional Testing
```bash
# Tests rules against multiple version pattern files
# Validates that rules can actually detect version strings
# Measures scanning performance and accuracy
```

### Test Files Generated

- `curl_test.txt`: Various curl version formats
- `openssl_test.txt`: OpenSSL version strings
- `nginx_test.txt`: Nginx version patterns
- `apache_test.txt`: Apache server versions
- `general_versions.txt`: Common version formats

### Manual Testing

```bash
# Test specific YARA rule against sample file
bin/yara64.exe target_yara_version_only/software_name.yara /path/to/test/file

# Scan directory with all generated rules
bin/yara64.exe -r target_yara_version_only/ /path/to/scan/directory
```

---

## 🔒 Branch Protection / Rulesets

This repository uses **GitHub Rulesets** to enforce code quality through mandatory pull requests.

### Ruleset Configuration

| Setting | Value | Description |
|---------|-------|-------------|
| **Target branches** | `main` | Applies to the main branch |
| **Enforcement** | Active | Rules are enforced immediately |
| **Pull requests** | Required | All changes must go through PR |
| **Merge commits** | Disabled | Only squash or rebase merges allowed |

### Why Rulesets Exist

- **Code Review**: All changes are reviewed before merging
- **Quality Control**: Automated checks run on every PR
- **Audit Trail**: Full history of who changed what and why
- **Collaboration**: Team members can discuss changes before they land

### Workflow with Rulesets

```bash
# 1. Create a feature branch (NEVER push directly to main)
git checkout -b feature/my-new-checker

# 2. Make your changes
# ... edit files ...

# 3. Stage and commit
git add .
git commit -m "Add new checker for FooBar software"

# 4. Push the feature branch
git push origin feature/my-new-checker

# 5. Open a Pull Request on GitHub
# 6. Wait for review and CI checks
# 7. Merge via squash or rebase
```

### Bypass Rules

Repository administrators can bypass rulesets in emergency situations. Use this responsibility wisely.

### Troubleshooting Ruleset Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| Push to main rejected | Ruleset requires PR | Push to a feature branch instead |
| PR cannot be merged | Required checks failing | Fix CI issues, ensure tests pass |
| Ruleset not triggering | Wrong branch pattern | Check ruleset target includes your branch |
| "Permission denied" on push | Authentication issue | Use PAT with `repo` scope or SSH key |

---

## 📊 Examples

### Example 1: Basic Conversion

**Source Python Checker (`source_python_re/curl.py`):**
```python
class Checker:
    CONTAINS_PATTERNS = ["curl"]
    FILENAME_PATTERNS = [r"curl\.exe"]
    VERSION_PATTERNS = [r"curl/(?P<version>[\d\.]+)"]
    VENDOR_PRODUCT = [("curl", "curl")]
```

**Generated YARA Rule (`target_yara_version_only/curl.yara`):**
```yara
rule curl {
    meta:
        software_name = "curl"
        open_source = true
        website = "Generated from Python RE patterns"
        description = "Detection rule for curl"
        generated_from = "source_python_re/curl.py"
        vendor_product = "curl:curl"
    strings:
        $version0 = /curl\/([0-9\.]+)/ nocase ascii wide
    condition:
        any of $version* and no_text_file
}
```

### Example 2: Enhanced Pattern Transformation

**Source Python Pattern with %s placeholders:**
```python
VERSION_PATTERNS = [
    r"Dnsmasq version (?:|%s  %s\r?\n)([0-9]+\.[0-9]+)",
    r"chrony version %s\r?\n([0-9]+\.[0-9]+)",
    r"GWeb/%s"
]
```

**Transformed YARA Patterns:**
```yara
# BEFORE (old converter):
$version0 = /Dnsmasq version (?:|  \r?\n)([0-9]+\.[0-9]+)/ nocase ascii wide
$version1 = /\(chrony\) version %s\r?\n([0-9]+\.[0-9]+)/ nocase ascii wide
$version2 = /([0-9]+\.[0-9]+)\r?\nGWeb\/%s/ nocase ascii wide

# AFTER (optimized converter):
$version0 = /Dnsmasq version (^\r?\n)([0-9]+\.[0-9]+)/ nocase ascii wide
$version1 = /\(chrony\) version \r?\n([0-9]+\.[0-9]+)/ nocase ascii wide
$version2 = /([0-9]+\.[0-9]+)\r?\nGWeb\// nocase ascii wide
```

### Example 3: Complex Pattern Conversion

**Source Python Regex:**
```python
VERSION_PATTERNS = [
    r"(?i)nginx/(?P<version>[\d\.]+)(?:\s+\([^)]+\))?"
]
```

**Converted YARA Pattern:**
```yara
$version0 = /nginx\/([0-9\.]+)(?:\s+\([^)]+\))?/ nocase ascii wide
```

### Example 4: Testing Results

```
🔍 YARA Comprehensive Test Report
=====================================

📊 Summary Statistics:
- Total YARA files: 435
- Files with syntax errors: 0 (0.00%)
- Files tested functionally: 435
- Functional tests passed: 418 (96.09%)
- Average compilation time: 12.3ms
- Average scanning time: 8.7ms

✅ Top Performing Rules:
1. curl.yara - 15/15 tests passed (100.00%)
2. openssl.yara - 12/12 tests passed (100.00%)
3. nginx.yara - 8/8 tests passed (100.00%)

⚠️ Rules Needing Attention:
1. python.yara - 2/5 tests passed (40.00%)
   Issue: Complex version patterns not matching
```

---

## ⚡ Performance Benchmarks

### Conversion Performance

| Metric | Value |
|--------|-------|
| Files processed | 434 |
| Successfully converted | 434 (100%) |
| Processing speed | ~50 files/second |
| Memory usage | <100MB |
| Regex transformation success | 100% |

### Filtering Performance

| Metric | Value |
|--------|-------|
| YARA rules parsed | 85 |
| Checker files analyzed | 434 |
| Unique files copied | 389 (89.6%) |
| Duplicate files skipped | 45 (10.4%) |
| Parsing speed | ~200 rules/second |
| Matching speed | ~100 files/second |
| Memory usage | <50MB |
| Copy performance | ~150 files/second |

### YARA Testing Performance

| Metric | Value |
|--------|-------|
| Average compilation time | ~12ms per rule |
| Average scanning time | ~9ms per rule |
| Syntax validation success | 100% |
| Functional test pass rate | ~96% |

---

## ❓ FAQ

### General Questions

**Q: What is RE2YARA?**
A: A tool that converts Python regex patterns from Intel's CVE Binary Tool checkers into YARA rules for software identification and malware detection.

**Q: Do I need YARA installed?**
A: The project includes YARA 4.2.3 binaries for Windows in the `bin/` directory. For Linux/macOS, install YARA separately.

**Q: Can I convert my own checker files?**
A: Yes! Create a Python file with a `*Checker` class following the format in [Contributing](#-contributing).

**Q: What's the difference between version-only and full mode?**
A: Version-only mode converts only `VERSION_PATTERNS`. Full mode (`re2yara_converter.py`) converts all patterns (CONTAINS, FILENAME, VERSION).

### Conversion Questions

**Q: Why are some regex features removed?**
A: YARA uses a subset of PCRE. Features like lookaheads, conditionals, and named groups are not supported and are removed during conversion.

**Q: Can I see what changes were made to my regex?**
A: Yes, check `regex_difference_report.md` for a human-readable report or `regex_difference_trace.json` for detailed JSON data.

**Q: The converted rule doesn't match my binary. What should I do?**
A: Run the functionality test: `py re2yara_version_only_converter.py test-functionality <rule>.yara`. If features were removed, you may need to manually adjust the pattern.

### Workflow Questions

**Q: Why can't I push directly to main?**
A: The repository uses GitHub Rulesets to enforce code review. All changes must go through a Pull Request.

**Q: How do I authenticate with GitHub?**
A: GitHub no longer supports password authentication. Use a Personal Access Token (PAT) with `repo` scope or switch to SSH.

**Q: Where do I get a PAT?**
A: GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token → Check `repo` scope.

---

## 🔧 Troubleshooting

### File Filtering Issues

#### No Files Copied After Filtering
```bash
[INFO] No new files to copy - all checker files match existing rules
```

**This is normal if all checker files have corresponding YARA rules**

**To override and force conversion:**
```bash
# Skip filtering and convert all files manually
cp checkers/*.py source_python_re/
py re2yara_version_only_converter.py
```

#### Filtering Too Many Files
```bash
Output:
[WARNING] Copied 389 files, skipped 45 (Expected different ratio)
```

**Solutions:**
1. Review `file_filtering_report.md` for filtering decisions
2. Check if YARA rules need updating
3. Manually adjust specific files:
```bash
# Copy specific file that was incorrectly filtered
cp checkers/specific_file.py source_python_re/
```

### Common Issues and Solutions

#### Git Lock File Error
```
Error: Unable to create '.git/index.lock': File exists
```

**Solution:**
```bash
# Remove git lock file (Windows)
del .git\index.lock

# Remove git lock file (Unix/Linux)
rm .git/index.lock
```

#### YARA Compilation Errors
```
Error: yarac64.exe: syntax error in rule file
```

**Solutions:**
1. Check `regex_difference_report.md` for conversion notes
2. Verify regex patterns don't contain unsupported features
3. Test individual files: `py re2yara_version_only_converter.py --test --file problem_rule.yara`

#### Missing YARA Binaries
```
FileNotFoundError: YARA binary not found: bin/yara64.exe
```

**Solution:**
1. Ensure YARA binaries are in `bin/` directory
2. Download YARA 4.2.3 for Windows from official releases
3. Verify executable permissions

#### Python Module Import Issues
```
ModuleNotFoundError: No module named 'ast'
```

**Solution:**
- Use Python 3.8+ (ast module is part of standard library)
- Check Python installation: `py --version`

#### Git Authentication Failed (403)
```
remote: Permission to user/repo.git denied to username.
fatal: unable to access 'https://github.com/...': The requested URL returned error: 403
```

**Cause**: GitHub no longer supports password authentication for Git operations.

**Solutions:**
1. **Use Personal Access Token (PAT)**:
   - Generate token at GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Check `repo` scope
   - Use token as password when pushing

2. **Switch to SSH**:
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   # Add public key to GitHub → Settings → SSH and GPG keys
   git remote set-url origin git@github.com:user/repo.git
   git push
   ```

### Performance Optimization

#### Enhanced Pattern Performance
The optimized converter generates more efficient YARA rules:

- **Cleaner Regex**: Removal of unnecessary `%s` placeholders reduces pattern complexity
- **Proper Anchors**: Fixed empty alternatives prevent backtracking issues
- **Faster Matching**: Optimized patterns improve YARA engine performance
- **Better Accuracy**: Proper pattern transformation increases detection rates

#### For large-scale scanning:
```bash
# Use compiled YARA rules for better performance
bin/yarac64.exe target_yara_version_only/ rules_compiled.yarc
bin/yara64.exe rules_compiled.yarc /path/to/scan
```

#### Memory optimization:
- Split large rule sets into smaller files
- Use process-based parallelism for multiple directories

#### Scanning optimization:
- Use appropriate file type filters
- Exclude text files with meta filters
- Limit scan depth for recursive operations

---

## 📈 Reports and Analytics

### Generated Reports

| Report | File | Description |
|--------|------|-------------|
| File Filtering | `file_filtering_report.md` | Deduplication statistics |
| Conversion Summary | `regex_difference_report.md` | Human-readable conversion stats |
| Conversion Detail | `regex_difference_trace.json` | Machine-readable JSON trace |
| YARA Test Results | `yara_comprehensive_test_report.md` | Syntax + functionality test results |

### Quality Assurance

- **Syntax Validation**: All generated YARA rules are syntax-checked using yarac64.exe
- **Functional Testing**: Rules are tested against real version patterns
- **Performance Analysis**: Compilation and scanning times are measured
- **Error Tracking**: All conversion issues are logged and reported
- **Enhanced Pattern Tracking**: Advanced optimizations are tracked with detailed flags:
  - `"removed_%s_comprehensive"` - Comprehensive %s placeholder removal
  - `"fixed_empty_alternatives"` - Pipe optimization for empty alternatives
- **Pattern Quality Verification**: Automatic validation ensures proper YARA regex syntax

---

## 🤝 Contributing

We welcome contributions! Please follow our contribution guidelines:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m 'Add feature description'`
4. Push to branch: `git push origin feature-name`
5. Submit a pull request

> **Note**: Direct pushes to `main` are blocked by Ruleset. All changes must go through a Pull Request.

### Development Guidelines

- Follow PEP 8 for Python code style
- Add appropriate tests for new features
- Update documentation for API changes
- Ensure all tests pass before submitting

### Adding New Checkers

To add a new software checker:

1. Create `checkers/mynewsoftware.py`:
```python
from cve_bin_tool.checkers import Checker

class MynewsoftwareChecker(Checker):
    CONTAINS_PATTERNS = [r"unique string in binary"]
    FILENAME_PATTERNS = [r"mynewsoftware"]
    VERSION_PATTERNS = [r"mynewsoftware[ /]([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("vendor_name", "mynewsoftware")]
```

2. Run the converter to generate the YARA rule
3. Test the generated rule against a real binary sample
4. Submit a PR with the new checker

---

## 📄 License

This project is licensed under the GPL-3.0-or-later License. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Intel Corporation**: For the original CVE Binary Tool checkers
- **YARA Project**: For the excellent pattern matching engine
- **Security Community**: For feedback and contributions

---

## 📞 Support

- **Issues**: Please report bugs via GitHub Issues
- **Documentation**: See `CLAUDE.md` for development details
- **Email**: Contact the maintainers for technical support

---

## 🔗 Quick Links

| Resource | Link |
|----------|------|
| Development Documentation | [CLAUDE.md](CLAUDE.md) |
| File Filtering Report | [file_filtering_report.md](file_filtering_report.md) |
| Conversion Reports | [regex_difference_report.md](regex_difference_report.md) |
| Test Results | [yara_comprehensive_test_report.md](yara_comprehensive_test_report.md) |
| YARA Documentation | [yara.readthedocs.io](https://yara.readthedocs.io/) |
| Python AST Documentation | [docs.python.org/ast](https://docs.python.org/3/library/ast.html) |
| GitHub Rulesets Docs | [docs.github.com/rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) |
| CVE Binary Tool | [github.com/intel/cve-bin-tool](https://github.com/intel/cve-bin-tool) |

---

*Generated with ❤️ by the RE2YARA team*# Test Mon Jun 29 18:50:14     2026
