# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Python RE to YARA Rules Converter** that transforms Python regular expression patterns from Intel's CVE Binary Tool checkers into YARA rules for malware detection and software identification. The project successfully converts 434 Python checker files with a 100% success rate.

## Core Commands

### Main Conversion Operations
```bash
# Convert all Python checker files to YARA rules (full conversion with all patterns)
py re2yara_converter.py

# Convert VERSION_PATTERNS only (Version-only mode - conversion only)
py re2yara_version_only_converter.py

# The script will:
# - Read all .py files from source_python_re/ (except __init__.py)
# - Generate .yara files in target_yara_version_only/
# - Create regex_difference_report.md and regex_difference_trace.json with statistics
# - No YARA testing performed (default behavior)
```

### Directory Management
```bash
# View conversion progress
ls target_yara/                    # 完整YARA规则
ls target_yara_version_only/       # 仅VERSION_PATTERNS规则
ls source_python_re/ | wc -l      # 应显示436个文件 (包括__init__.py)

# Check existing signature formats
ls signatures/

# 查看转换统计报告 (版本转换器生成 - 项目根目录)
cat regex_difference_report.md
# 详细追踪报告 (JSON格式 - 项目根目录)
cat regex_difference_trace.json
# YARA综合测试报告 (新功能 - 项目根目录)
cat yara_comprehensive_test_report.md
# 完整转换器报告 (如需要)
cat target_yara/conversion_report.md
```

### Validation and Testing
```bash
# Test generated YARA rules (using local YARA binary)
bin/yara64.exe target_yara/software_name.yara /path/to/test/file

# Scan with all generated rules
bin/yara64.exe -r target_yara/ /path/to/scan/directory

# NEW: Independent testing subcommands
py re2yara_version_only_converter.py                    # Convert only (default behavior)
py re2yara_version_only_converter.py test-syntax        # Test syntax of all YARA files
py re2yara_version_only_converter.py test-functionality # Test functionality of all YARA files
py re2yara_version_only_converter.py test-syntax file.yara          # Test syntax of specific file
py re2yara_version_only_converter.py test-functionality file.yara   # Test functionality of specific file

# LEGACY: Old --test argument (deprecated but still supported)
py re2yara_version_only_converter.py --test        # Comprehensive testing (both syntax + functionality)

# Manual testing of specific VERSION_PATTERNS-only rules
bin/yara64.exe target_yara_version_only/software_name_version_only.yara /path/to/test/file
```

## Architecture

### Core Components

#### **re2yara_converter.py:324** - Main Conversion Engine
- `RE2YARAConverter` class handles the complete conversion pipeline
- Uses Python's `ast` module to parse checker classes (no external dependencies)
- Implements regex transformation from Python RE to YARA-compatible patterns

#### **Source Data Pipeline**
```
source_python_re/*.py → AST Parsing → Pattern Extraction → Regex Transformation → YARA Generation
```

#### **Key Data Structures**
Each Python checker file contains a `Checker` class with these attributes:
- `CONTAINS_PATTERNS`: String content for software detection
- `FILENAME_PATTERNS`: Regex patterns for filename matching
- `VERSION_PATTERNS`: Regex for version extraction
- `VENDOR_PRODUCT`: Vendor-product tuples for CVE database integration

### Pattern Transformation Pipeline

The converter handles major differences between Python and YARA regex:

1. **Named Groups**: `(?P<name>...)` → `(?:...)` (non-capturing groups)
2. **Conditional Groups**: `(?(...)...)` → Removed (YARA doesn't support)
3. **Lookaheads/Lookbehinds**: `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)` → Removed
4. **Possessive Quantifiers**: `++`, `*+`, `?+` → Standard `+`, `*`, `?`

### YARA Rule Generation Format

Generated rules follow the established pattern in `signatures/software.yara:18`:
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

## Important Patterns and Conventions

### Meta Filter Usage
All generated rules include `and no_text_file` condition using the private rule from `signatures/00_meta_filter.yara:3` to reduce false positives by excluding text files.

### String Matching Strategies
- **Simple strings**: Use literal format `"text"` for patterns without regex characters
- **Complex patterns**: Use regex format `/pattern/` with proper escaping
- **Character encoding**: Always include `nocase ascii wide` for comprehensive matching

### Error Handling and Tracking
The converter maintains detailed statistics:
- Total files processed
- Successfully converted files
- Failed conversions with error details
- Conversion notes documenting regex simplifications

## Development Workflow

### Adding New Source Patterns
1. Place Python checker files in `source_python_re/`
2. Ensure each file contains a `Checker` class with required attributes
3. Run `python re2yara_converter.py` to generate corresponding YARA rules

### Testing Generated Rules
1. Verify YARA syntax: `yara target_yara/rule.yara /dev/null` (should produce no syntax errors)
2. Test against known samples to validate detection capabilities
3. Review `conversion_report.md` for any conversion issues

### Debugging Conversion Issues
- Check `conversion_stats['conversion_notes']` for regex transformation warnings
- Verify AST parsing succeeded for all source files
- Review generated YARA files for pattern correctness

## Key File Locations

- **Main converter**: `re2yara_converter.py:20` (RE2YARAConverter class)
- **Version-only converter**: `re2yara_version_only_converter.py:22` (RE2YARAVersionOnlyConverter + YARATestSuite classes)
  - Updated behavior:
    - Default mode: Only conversion, no automatic testing
    - Testing mode: Only testing, no conversion
    - Use `--test` flag to enable YARA testing functionality
    - Supports testing all rules or specific files
    - Generates comprehensive test reports and performance metrics
- **Source patterns**: `source_python_re/*.py` (434 checker files)
- **Target output**: `target_yara/*.yara` (完整生成的规则)
- **Version-only output**: `target_yara_version_only/*.yara` (仅VERSION_PATTERNS规则)
- **Reference formats**: `signatures/*.yara` (existing YARA rule patterns)
- **Conversion report**: `target_yara/conversion_report.md` (detailed statistics)
- **Regex difference report**: `regex_difference_report.md` (正则差异追踪 - 项目根目录)
- **Detailed trace report**: `regex_difference_trace.json` (详细JSON追踪 - 项目根目录)
- **YARA comprehensive test report**: `yara_comprehensive_test_report.md` (全面测试结果 - 项目根目录)
- **YARA binaries**: `bin/yara64.exe`, `bin/yarac64.exe` (YARA 4.2.3)

### Comprehensive YARA Testing Framework
- **Updated behavior**: Default mode only converts, no automatic testing
- **Testing mode**: Only testing, no conversion
- **Simplified arguments**: Removed `--no-test` parameter for cleaner interface

#### **YARATestSuite Class**
- **Syntax Validation**: Uses `yarac64.exe` to compile and validate all generated YARA rules
- **Functional Testing**: Tests rules against generated test files with common version patterns
- **Performance Analysis**: Measures compilation and scanning times for all rules
- **Automated Test Files**: Creates diverse test cases for version pattern matching

#### **Testing Features**
- **Phase 1 - Syntax Validation**:
  - Compiles all YARA rules using yarac64.exe
  - Reports syntax errors with detailed messages
  - Measures compilation performance
- **Phase 2 - Functional Testing**:
  - Tests rules against multiple version pattern files
  - Validates that rules can actually detect version strings
  - Measures scanning performance and accuracy
- **Comprehensive Reporting**:
  - Detailed test results with success/failure analysis
  - Performance metrics and recommendations
  - Error analysis and improvement suggestions

#### **Test Files Generated**
- `curl_test.txt`: Various curl version formats
- `openssl_test.txt`: OpenSSL version strings
- `nginx_test.txt`: Nginx version patterns
- `apache_test.txt`: Apache server versions
- `general_versions.txt`: Common version formats

## Technology Stack

- **Python 3.8+**: Standard library only (ast, re, pathlib)
  - **运行环境**: Windows环境下使用`py`命令执行Python脚本
- **YARA 4.2.3**: Pattern matching swiss army knife
  - **Windows二进制**: `bin/yara64.exe`和`bin/yarac64.exe`
  - **编译工具**: `bin/yarac64.exe`用于编译YARA规则
- **AST Parsing**: Extract pattern attributes from Python classes
- **No external dependencies**: Converter uses only Python standard library

## Common Issues and Solutions

### Regex Compatibility
- Python-specific features are automatically simplified
- Conditional groups and lookaheads are removed with notes in conversion report
- Backslash escaping is handled for YARA syntax

### File Structure Requirements
- Source files must contain classes ending with 'Checker'
- Class attributes must be exactly named: CONTAINS_PATTERNS, FILENAME_PATTERNS, VERSION_PATTERNS, VENDOR_PRODUCT
- Target directory is created automatically if it doesn't exist