---
name: re2yara
description: Convert Python regular expression patterns from CVE Binary Tool checker files into YARA detection rules. Use when working with checker classes, VERSION_PATTERNS, CONTAINS_PATTERNS, FILENAME_PATTERNS, or when generating/testing YARA rules for software identification and malware detection. Also use when debugging Python-to-YARA regex conversion issues or when writing new checker files for CVE scanning.
---

# RE2YARA - Python RE to YARA Rules Converter

Converts Python regex patterns from Intel's CVE Binary Tool checkers into YARA rules for software identification and malware detection. 434+ checkers supported with 100% conversion success.

## When to Use This Skill

Trigger on requests involving:
- Converting Python checker files (Checker classes) to YARA rules
- VERSION_PATTERNS, CONTAINS_PATTERNS, FILENAME_PATTERNS extraction
- Regex transformation from Python RE syntax to YARA-compatible syntax
- Testing/validating generated YARA rules (syntax or functionality)
- Writing new checker files for CVE Binary Tool
- Debugging YARA compilation errors from converted patterns
- Running the converter script or interpreting its reports

## Quick Reference

### Project Layout
```
re2yara/
├── re2yara_version_only_converter.py  # Main converter (VERSION_PATTERNS only)
├── file_filter_dedup.py               # Filter checkers against existing YARA signatures
├── checkers/                          # 435 Python checker files (source input)
│   ├── __init__.py                    # Checker base class + metaclass
│   └── <software>.py                  # Individual checker definitions
├── signatures/                        # Reference YARA rules (14 files)
│   ├── 00_meta_filter.yara            # no_text_file private rule
│   └── software.yara                  # Template + example rules
├── bin/
│   ├── yara64.exe                     # YARA scanner
│   └── yarac64.exe                    # YARA compiler (syntax validation)
├── source_python_re/                  # Filtered checkers (working copy)
└── target_yara_version_only/          # Generated YARA output
```

### Essential Commands

```bash
# === CONVERSION ===
# Convert all VERSION_PATTERNS to YARA (default)
py re2yara_version_only_converter.py

# Convert with custom paths
py re2yara_version_only_converter.py -s checkers/ -t output/

# Verbose debugging
py re2yara_version_only_converter.py -v

# === TESTING ===
# Validate YARA syntax of all generated rules
py re2yara_version_only_converter.py test-syntax

# Validate syntax of one rule
py re2yara_version_only_converter.py test-syntax target_yara_version_only/curl_version_only.yara

# Test rule matches against sample files
py re2yara_version_only_converter.py test-functionality

# Test one rule's functionality
py re2yara_version_only_converter.py test-functionality target_yara_version_only/curl_version_only.yara

# === MANUAL YARA TESTING ===
# Scan a file with a rule
bin/yara64.exe target_yara_version_only/curl_version_only.yara path/to/file

# Recursive directory scan
bin/yara64.exe -r target_yara_version_only/ path/to/scan/

# Compile-check syntax manually
bin/yarac64.exe rule.yara compiled.yc

# === FILE FILTERING ===
# Copy checkers to source_python_re/ excluding duplicates of existing signatures
py file_filter_dedup.py
```

## Checker File Format

Each checker is a Python class inheriting from `Checker` with four attributes:

```python
class CurlChecker(Checker):
    CONTAINS_PATTERNS = [r"Dump libcurl equivalent code of this command line"]
    FILENAME_PATTERNS = [r"curl"]
    VERSION_PATTERNS = [r"\r?\ncurl[ -]([678]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("haxx", "curl")]
```

**Attribute semantics:**
- `CONTAINS_PATTERNS` — Strings/regexes that indicate the software is present in a binary
- `FILENAME_PATTERNS` — Regexes matching the filename of the software binary
- `VERSION_PATTERNS` — Regexes that capture the version number (these are what get converted in version-only mode)
- `VENDOR_PRODUCT` — List of (vendor, product) tuples for CVE database lookup; must be lowercase

The `CheckerMetaClass` metaclass compiles all regex patterns at class definition time and validates that `VENDOR_PRODUCT` entries are lowercase.

## Generated YARA Rule Format

```yara
rule curl_version_only
{
    meta:
        software_name = "Curl"
        open_source = true
        website = "Generated from Python VERSION_PATTERNS only"
        description = "Version detection rule for Curl"
        generated_from = "source_python_re/curl.py"
        conversion_mode = "version_only"
        vendor_product = "haxx:curl"
    strings:
        $version0 = /\r?\ncurl[ -]([678]+\.[0-9]+\.[0-9]+)/ nocase ascii wide
    condition:
        any of them
}
```

**Naming convention:** `{filename}_version_only` with `.`/`-`/` ` → `_`. Prefix with `_` if starts with digit.

## Python RE → YARA Regex Transformation Pipeline

The converter applies these transformations in order. When debugging conversion issues, check each stage:

| # | Python Feature | YARA Conversion | Notes |
|---|---------------|-----------------|-------|
| 1 | `%s` placeholders | Removed with surrounding space cleanup | Format strings aren't valid regex |
| 2 | `(\|pattern)` empty alternatives | `(^pattern)` | Fixes empty alternation start |
| 3 | `.*?` lazy dot-star | `[^\x0A\x0D]*` | YARA has no lazy `.*` with single-line semantics |
| 4 | `\-` in char classes | Moved to end of class | `[a\-z]` → `[az-]` avoids range ambiguity |
| 5 | `(?:...)` non-capturing | `(...)` capturing | YARA doesn't support non-capturing groups |
| 6 | `\r?\n` at pattern start | `(^\|\r?\n)` | Anchors to line start or newline |
| 7 | `(?P<name>...)` named groups | `(?:...)` → `(...)` | YARA has no named groups |
| 8 | `(?(...)...)` conditional | Removed | YARA doesn't support conditionals |
| 9 | `(?=...) / (?!...)` lookaround | Removed | YARA doesn't support lookaheads |
| 10 | `(?<=...) / (?<!...)` lookbehind | Removed | YARA doesn't support lookbehinds |
| 11 | `++ / *+ / ?+` possessive | `+ / * / ?` | YARA doesn't support possessive quantifiers |
| 12 | `/` forward slash | `\/` escaped | `/` is YARA regex delimiter |
| 13 | Reversed ranges `[z-a]` | Fixed to `[a-z]` | Character range correction |
| 14 | Unbalanced `[]` brackets | Balanced | Adds/removes missing brackets |

## Converter Architecture

### RE2YARAVersionOnlyConverter

- `extract_class_info(file_path)` — AST-parses the Python file, finds the `*Checker` class, extracts `VERSION_PATTERNS` and `VENDOR_PRODUCT`
- `_process_attribute(attr_name, attr_value, class_info)` — Handles both `ast.Assign` and `ast.AnnAssign` nodes
- `python_to_yara_regex(python_regex, source_info)` — Applies the 14-stage transformation pipeline above
- `generate_yara_rule(class_info)` — Assembles the YARA rule string
- `convert_file(source_file)` / `convert_all()` — Batch processing
- `generate_regex_difference_report()` — Writes `regex_difference_report.md` and `regex_difference_trace.json`

### YARATestSuite

- `create_test_files()` — Generates sample test files (curl, openssl, nginx, apache, general_versions) in `test_generated_files/`
- `test_yara_syntax(yara_file)` — Compiles rule with `yarac64.exe`, reports errors
- `test_yara_functionality(yara_file, test_files)` — Runs `yara64.exe` against sample files
- `test_all_yara_rules(directory)` — Full pipeline: syntax → functionality
- Report generators: `generate_test_report()`, `generate_syntax_report()`, `generate_functionality_report()`

## Reports and Outputs

| File | Content |
|------|---------|
| `regex_difference_report.md` | Summary of regex transformations per file |
| `regex_difference_trace.json` | Full JSON trace with before/after patterns |
| `yara_syntax_test_report.md` | Syntax validation results for all rules |
| `yara_functionality_test_report.md` | Match results against test samples |
| `yara_comprehensive_test_report.md` | Legacy combined report (deprecated --test mode) |

## Writing New Checkers

To add a new software checker:

1. Create `checkers/mynewsoftware.py`:

```python
from cve_bin_tool.checkers import Checker

class MynewsoftwareChecker(Checker):
    CONTAINS_PATTERNS = [
        r"unique string found in mynewsoftware binary",
    ]
    FILENAME_PATTERNS = [
        r"mynewsoftware",
    ]
    VERSION_PATTERNS = [
        r"mynewsoftware[ /]([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("vendor_name", "mynewsoftware")]
```

2. Run the converter to generate the YARA rule
3. Test the generated rule against a real binary sample
4. Add reference samples to `test_generated_files/` if needed

**VERSION_PATTERNS tips:**
- Use raw strings (`r"..."`) for regex patterns
- Capture version with `([0-9]+\.[0-9]+)` or similar
- Account for common prefixes: `software-`, `software/`, `software `
- Test against real `strings` output from target binaries before relying on the rule

## Troubleshooting

### YARA syntax errors after conversion
Run: `py re2yara_version_only_converter.py test-syntax target_yara_version_only/problematic.yara`
Then inspect the rule: the most common issues are:
- Unescaped `/` inside the regex pattern → should be `\/`
- Unbalanced `[]` or `()` — check the original Python pattern
- Lone backslashes — Python `\d` should survive conversion; `\\` may indicate double-escaping

### Rule doesn't match real files
- Run functionality test: `py re2yara_version_only_converter.py test-functionality <rule>.yara`
- Check if the lookaround/conditional was removed — these features are stripped silently. Manual rewrite needed.
- Verify `nocase ascii wide` flags are appropriate; drop `wide` if the target is ASCII-only

### Conversion fails for a checker file
- Run with `-v` (verbose) to see AST parsing debug output
- The checker class must be named `*Checker` (suffix match)
- `VERSION_PATTERNS` must be a list of strings (ast.List), not a variable reference or function call

### Empty condition / "false" in generated rule
- The checker had no `VERSION_PATTERNS` or they were all empty
- Check that patterns aren't commented out in the source file

### Performance issues with generated rules
- Avoid `.*` at pattern start — causes full-string scans
- YARA's `nocase` doubles alphabet size; use case-sensitive matching if the pattern is case-specific
- Multiple `$versionN` strings with `any of them` is efficient; boolean `or` chains are not

## Meta Filter

All generated rules reference the `no_text_file` private rule from `signatures/00_meta_filter.yara`:

```yara
import "magic"

private rule no_text_file
{
    condition:
        (magic.mime_type() != "text/plain" and magic.mime_type() != "text/html") or test_flag
}
```

This excludes plain text and HTML files from matching (reduces false positives). The `test_flag` variable allows bypassing during testing. Rules must be scanned with the meta filter imported, or the `and no_text_file` clause must be removed for standalone use.
