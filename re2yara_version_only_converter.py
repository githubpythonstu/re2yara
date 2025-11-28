#!/usr/bin/env python3
"""
Python RE VERSION_PATTERNS to YARA Rules Converter (Version-Only Mode)

This script converts only VERSION_PATTERNS from Python checker classes
to YARA rules for version detection with focused traceability.

Copyright (C) 2024
SPDX-License-Identifier: GPL-3.0-or-later
"""

import os
import re
import ast
import importlib.util
import json
import subprocess
import tempfile
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from datetime import datetime


class YARATestSuite:
    """Comprehensive testing suite for generated YARA rules"""

    def __init__(self, yara_binary_path: str, yarac_binary_path: str):
        self.yara_binary = Path(yara_binary_path)
        self.yarac_binary = Path(yarac_binary_path)
        self.test_results = {
            'syntax_tests': [],
            'functional_tests': [],
            'performance_tests': [],
            'summary': {
                'total_rules': 0,
                'syntax_passed': 0,
                'syntax_failed': 0,
                'functional_passed': 0,
                'functional_failed': 0,
                'test_timestamp': datetime.now().isoformat()
            }
        }

        # Verify YARA binaries exist
        if not self.yara_binary.exists():
            raise FileNotFoundError(f"YARA binary not found: {self.yara_binary}")
        if not self.yarac_binary.exists():
            raise FileNotFoundError(f"YARA compiler binary not found: {self.yarac_binary}")

    def create_test_files(self) -> Dict[str, Path]:
        """Create test files with version patterns for functional testing"""
        test_dir = Path("test_generated_files")
        test_dir.mkdir(exist_ok=True)

        test_files = {}

        # Common version patterns to test against
        version_samples = {
            'curl_test.txt': [
                "curl 7.68.0\n",
                "curl 8.1.2\n",
                "Some other content\n",
                "curl/7.78.0\n"
            ],
            'openssl_test.txt': [
                "OpenSSL 1.1.1f  31 Mar 2020\n",
                "OpenSSL 3.0.2 15 May 2022\n",
                "Some other content\n",
                "OpenSSL 1.1.1k  25 Mar 2021\n"
            ],
            'nginx_test.txt': [
                "nginx/1.18.0\n",
                "nginx/1.20.1\n",
                "Some other content\n",
                "nginx version: nginx/1.21.0\n"
            ],
            'apache_test.txt': [
                "Apache/2.4.41\n",
                "Apache/2.4.46\n",
                "Some other content\n",
                "Server: Apache/2.4.48\n"
            ],
            'general_versions.txt': [
                "version 1.0.0\n",
                "v2.1.3\n",
                "Software 3.4.5\n",
                "release 4.5.6\n"
            ]
        }

        for filename, content in version_samples.items():
            test_file = test_dir / filename
            with open(test_file, 'w', encoding='utf-8') as f:
                f.writelines(content)
            test_files[filename] = test_file

        return test_files

    def test_yara_syntax(self, yara_file: Path) -> Dict:
        """Test YARA rule syntax using yarac compiler"""
        test_result = {
            'rule_file': str(yara_file),
            'syntax_valid': False,
            'error_message': None,
            'compilation_time': None,
            'rule_size': yara_file.stat().st_size if yara_file.exists() else 0
        }

        if not yara_file.exists():
            test_result['error_message'] = f"YARA file not found: {yara_file}"
            return test_result

        start_time = datetime.now()

        try:
            # Use yarac to compile and check syntax
            # yarac requires input file and output file
            compiled_output = yara_file.with_suffix('.yc')
            result = subprocess.run(
                [str(self.yarac_binary), str(yara_file), str(compiled_output)],
                capture_output=True,
                text=True,
                timeout=30  # 30 second timeout
            )

            # Clean up compiled output file if it was created
            if compiled_output.exists():
                compiled_output.unlink()

            test_result['compilation_time'] = (datetime.now() - start_time).total_seconds()

            if result.returncode == 0:
                test_result['syntax_valid'] = True
            else:
                test_result['error_message'] = result.stderr.strip()

        except subprocess.TimeoutExpired:
            test_result['error_message'] = "Compilation timeout (30s)"
        except Exception as e:
            test_result['error_message'] = f"Compilation error: {str(e)}"

        return test_result

    def test_yara_functionality(self, yara_file: Path, test_files: Dict[str, Path]) -> Dict:
        """Test YARA rule functionality against test files"""
        functional_result = {
            'rule_file': str(yara_file),
            'matches': {},
            'total_scans': 0,
            'successful_scans': 0,
            'scan_time': 0,
            'errors': []
        }

        if not yara_file.exists():
            functional_result['errors'].append(f"YARA file not found: {yara_file}")
            return functional_result

        start_time = datetime.now()

        # Test against all generated test files
        for test_name, test_file in test_files.items():
            if not test_file.exists():
                functional_result['errors'].append(f"Test file not found: {test_file}")
                continue

            functional_result['total_scans'] += 1

            try:
                # Run YARA scan
                result = subprocess.run(
                    [str(self.yara_binary), str(yara_file), str(test_file)],
                    capture_output=True,
                    text=True,
                    timeout=15  # 15 second timeout per scan
                )

                scan_result = {
                    'test_file': str(test_file),
                    'return_code': result.returncode,
                    'stdout': result.stdout.strip(),
                    'stderr': result.stderr.strip(),
                    'matched': result.returncode == 0 and bool(result.stdout.strip())
                }

                functional_result['matches'][test_name] = scan_result

                if result.returncode == 0:
                    functional_result['successful_scans'] += 1

            except subprocess.TimeoutExpired:
                functional_result['matches'][test_name] = {
                    'test_file': str(test_file),
                    'error': 'Scan timeout (15s)'
                }
                functional_result['errors'].append(f"Scan timeout for {test_name}")
            except Exception as e:
                functional_result['matches'][test_name] = {
                    'test_file': str(test_file),
                    'error': str(e)
                }
                functional_result['errors'].append(f"Scan error for {test_name}: {str(e)}")

        functional_result['scan_time'] = (datetime.now() - start_time).total_seconds()

        return functional_result

    def test_all_yara_rules(self, yara_directory: Path) -> Dict:
        """Test all YARA rules in a directory"""
        print(f"\n{'='*60}")
        print(f"COMPREHENSIVE YARA RULES TESTING")
        print(f"{'='*60}")

        # Create test files
        print("Creating test files...")
        test_files = self.create_test_files()

        # Find all YARA files
        yara_files = list(yara_directory.glob("*.yara"))
        self.test_results['summary']['total_rules'] = len(yara_files)

        print(f"Found {len(yara_files)} YARA rules to test")
        print(f"Using YARA binary: {self.yara_binary}")
        print(f"Using YARA compiler: {self.yarac_binary}")

        # Test syntax for all rules
        print(f"\n{'-'*40}")
        print("PHASE 1: SYNTAX VALIDATION")
        print(f"{'-'*40}")

        for i, yara_file in enumerate(yara_files, 1):
            print(f"[{i:3d}/{len(yara_files)}] Testing syntax: {yara_file.name}")

            syntax_result = self.test_yara_syntax(yara_file)
            self.test_results['syntax_tests'].append(syntax_result)

            if syntax_result['syntax_valid']:
                self.test_results['summary']['syntax_passed'] += 1
                print(f"         [OK] Syntax OK ({syntax_result['compilation_time']:.3f}s)")
            else:
                self.test_results['summary']['syntax_failed'] += 1
                print(f"         [ERROR] Syntax Error: {syntax_result['error_message']}")

        # Test functionality for rules that passed syntax
        syntax_passed_files = [
            yara_files[i] for i, result in enumerate(self.test_results['syntax_tests'])
            if result['syntax_valid']
        ]

        print(f"\n{'-'*40}")
        print("PHASE 2: FUNCTIONAL TESTING")
        print(f"{'-'*40}")

        for i, yara_file in enumerate(syntax_passed_files, 1):
            print(f"[{i:3d}/{len(syntax_passed_files)}] Testing functionality: {yara_file.name}")

            functional_result = self.test_yara_functionality(yara_file, test_files)
            self.test_results['functional_tests'].append(functional_result)

            if functional_result['successful_scans'] > 0:
                self.test_results['summary']['functional_passed'] += 1
                matches = sum(1 for match in functional_result['matches'].values()
                             if match.get('matched', False))
                print(f"         [OK] Functional OK ({matches}/{len(functional_result['matches'])} files matched) ({functional_result['scan_time']:.3f}s)")
            else:
                self.test_results['summary']['functional_failed'] += 1
                print(f"         [ERROR] No matches detected ({functional_result['scan_time']:.3f}s)")

                # Show errors if any
                for error in functional_result['errors']:
                    print(f"           Error: {error}")

        return self.test_results

    def test_syntax_only(self, yara_file: Path) -> Dict:
        """Test YARA rule syntax only (standalone method)"""
        print(f"\n{'='*60}")
        print(f"SYNTAX TESTING: {yara_file.name}")
        print(f"{'='*60}")

        syntax_result = self.test_yara_syntax(yara_file)

        test_results = {
            'syntax_tests': [syntax_result],
            'summary': {
                'total_rules': 1,
                'syntax_passed': 1 if syntax_result['syntax_valid'] else 0,
                'syntax_failed': 0 if syntax_result['syntax_valid'] else 1,
                'test_timestamp': datetime.now().isoformat()
            }
        }

        print(f"[{'OK' if syntax_result['syntax_valid'] else 'ERROR'}] {yara_file.name}")
        if syntax_result['syntax_valid']:
            print(f"   Syntax: Valid ({syntax_result['compilation_time']:.3f}s)")
        else:
            print(f"   Syntax: Invalid - {syntax_result['error_message']}")

        return test_results

    def test_syntax_all(self, yara_directory: Path) -> Dict:
        """Test syntax for all YARA rules in a directory"""
        print(f"\n{'='*60}")
        print(f"SYNTAX TESTING OF ALL YARA RULES")
        print(f"{'='*60}")

        # Find all YARA files
        yara_files = list(yara_directory.glob("*.yara"))

        test_results = {
            'syntax_tests': [],
            'summary': {
                'total_rules': len(yara_files),
                'syntax_passed': 0,
                'syntax_failed': 0,
                'test_timestamp': datetime.now().isoformat()
            }
        }

        print(f"Found {len(yara_files)} YARA rules to test")
        print(f"Using YARA compiler: {self.yarac_binary}")

        for i, yara_file in enumerate(yara_files, 1):
            print(f"[{i:3d}/{len(yara_files)}] Testing: {yara_file.name}")

            syntax_result = self.test_yara_syntax(yara_file)
            test_results['syntax_tests'].append(syntax_result)

            if syntax_result['syntax_valid']:
                test_results['summary']['syntax_passed'] += 1
                print(f"         [OK] Syntax Valid ({syntax_result['compilation_time']:.3f}s)")
            else:
                test_results['summary']['syntax_failed'] += 1
                print(f"         [ERROR] Syntax Error: {syntax_result['error_message']}")

        # Summary
        total = test_results['summary']['total_rules']
        passed = test_results['summary']['syntax_passed']
        failed = test_results['summary']['syntax_failed']
        success_rate = (passed / total) * 100 if total > 0 else 0

        print(f"\n{'='*60}")
        print(f"SYNTAX TESTING SUMMARY")
        print(f"{'='*60}")
        print(f"Total rules tested: {total}")
        print(f"Syntax passed: {passed}")
        print(f"Syntax failed: {failed}")
        print(f"Success rate: {success_rate:.1f}%")

        return test_results

    def test_functionality_only(self, yara_file: Path) -> Dict:
        """Test YARA rule functionality only (standalone method)"""
        print(f"\n{'='*60}")
        print(f"FUNCTIONALITY TESTING: {yara_file.name}")
        print(f"{'='*60}")

        # Create test files
        print("Creating test files...")
        test_files = self.create_test_files()

        functional_result = self.test_yara_functionality(yara_file, test_files)

        test_results = {
            'functional_tests': [functional_result],
            'summary': {
                'total_rules': 1,
                'functional_passed': 1 if functional_result['successful_scans'] > 0 else 0,
                'functional_failed': 0 if functional_result['successful_scans'] > 0 else 1,
                'test_timestamp': datetime.now().isoformat()
            }
        }

        matches = sum(1 for match in functional_result['matches'].values()
                     if match.get('matched', False))

        print(f"[{'OK' if functional_result['successful_scans'] > 0 else 'ERROR'}] {yara_file.name}")
        print(f"   Functional: {'Valid' if functional_result['successful_scans'] > 0 else 'Invalid'}")
        print(f"   Matches: {matches}/{len(functional_result['matches'])} test files")
        print(f"   Scan time: {functional_result['scan_time']:.3f}s")

        # Show detailed match results
        if matches > 0:
            print(f"\nDETAILED MATCH RESULTS:")
            for test_name, match_data in functional_result['matches'].items():
                if match_data.get('matched', False):
                    print(f"   [MATCH] {test_name}: {match_data.get('stdout', 'Match found')}")
                else:
                    print(f"   [NO MATCH] {test_name}")

        return test_results

    def test_functionality_all(self, yara_directory: Path) -> Dict:
        """Test functionality for all YARA rules in a directory"""
        print(f"\n{'='*60}")
        print(f"FUNCTIONALITY TESTING OF ALL YARA RULES")
        print(f"{'='*60}")

        # Create test files
        print("Creating test files...")
        test_files = self.create_test_files()

        # Find all YARA files
        yara_files = list(yara_directory.glob("*.yara"))

        test_results = {
            'functional_tests': [],
            'summary': {
                'total_rules': len(yara_files),
                'functional_passed': 0,
                'functional_failed': 0,
                'test_timestamp': datetime.now().isoformat()
            }
        }

        print(f"Found {len(yara_files)} YARA rules to test")
        print(f"Using YARA binary: {self.yara_binary}")
        print(f"Test files created: {len(test_files)}")

        for i, yara_file in enumerate(yara_files, 1):
            print(f"[{i:3d}/{len(yara_files)}] Testing: {yara_file.name}")

            functional_result = self.test_yara_functionality(yara_file, test_files)
            test_results['functional_tests'].append(functional_result)

            if functional_result['successful_scans'] > 0:
                test_results['summary']['functional_passed'] += 1
                matches = sum(1 for match in functional_result['matches'].values()
                             if match.get('matched', False))
                print(f"         [OK] Functional Valid ({matches}/{len(functional_result['matches'])} files matched) ({functional_result['scan_time']:.3f}s)")
            else:
                test_results['summary']['functional_failed'] += 1
                print(f"         [ERROR] Functional Invalid ({functional_result['scan_time']:.3f}s)")

        # Summary
        total = test_results['summary']['total_rules']
        passed = test_results['summary']['functional_passed']
        failed = test_results['summary']['functional_failed']
        success_rate = (passed / total) * 100 if total > 0 else 0

        print(f"\n{'='*60}")
        print(f"FUNCTIONALITY TESTING SUMMARY")
        print(f"{'='*60}")
        print(f"Total rules tested: {total}")
        print(f"Functional passed: {passed}")
        print(f"Functional failed: {failed}")
        print(f"Success rate: {success_rate:.1f}%")

        return test_results

    def test_single_yara_file(self, yara_file: Path) -> Dict:
        """Test a single YARA file with comprehensive analysis"""
        print(f"\n{'='*60}")
        print(f"SINGLE YARA FILE TESTING: {yara_file.name}")
        print(f"{'='*60}")

        # Create test files
        print("Creating test files...")
        test_files = self.create_test_files()

        # Verify the YARA file exists
        if not yara_file.exists():
            print(f"[ERROR] YARA file not found: {yara_file}")
            return {
                'syntax_tests': [{
                    'rule_file': str(yara_file),
                    'syntax_valid': False,
                    'error_message': f"YARA file not found: {yara_file}",
                    'compilation_time': 0,
                    'rule_size': 0
                }],
                'functional_tests': [],
                'summary': {
                    'total_rules': 1,
                    'syntax_passed': 0,
                    'syntax_failed': 1,
                    'functional_passed': 0,
                    'functional_failed': 1,
                    'test_timestamp': datetime.now().isoformat()
                }
            }

        print(f"Testing file: {yara_file}")
        print(f"Using YARA binary: {self.yara_binary}")
        print(f"Using YARA compiler: {self.yarac_binary}")

        # Test syntax
        print(f"\n{'-'*40}")
        print("SYNTAX VALIDATION")
        print(f"{'-'*40}")

        syntax_result = self.test_yara_syntax(yara_file)
        self.test_results['syntax_tests'].append(syntax_result)

        if syntax_result['syntax_valid']:
            self.test_results['summary']['syntax_passed'] = 1
            print(f"[OK] Syntax OK ({syntax_result['compilation_time']:.3f}s)")

            # Test functionality if syntax passed
            print(f"\n{'-'*40}")
            print("FUNCTIONAL TESTING")
            print(f"{'-'*40}")

            functional_result = self.test_yara_functionality(yara_file, test_files)
            self.test_results['functional_tests'].append(functional_result)

            if functional_result['successful_scans'] > 0:
                self.test_results['summary']['functional_passed'] = 1
                matches = sum(1 for match in functional_result['matches'].values()
                             if match.get('matched', False))
                print(f"[OK] Functional OK ({matches}/{len(functional_result['matches'])} files matched) ({functional_result['scan_time']:.3f}s)")

                # Show detailed match results
                print(f"\n{'-'*40}")
                print("DETAILED MATCH RESULTS")
                print(f"{'-'*40}")

                for test_name, match_data in functional_result['matches'].items():
                    if match_data.get('matched', False):
                        print(f"[MATCH] {test_name}: MATCH FOUND")
                        if match_data.get('stdout'):
                            print(f"   {match_data['stdout']}")
                    else:
                        print(f"[NO MATCH] {test_name}: No match")
                        if match_data.get('stderr'):
                            print(f"   Error: {match_data['stderr']}")
            else:
                self.test_results['summary']['functional_failed'] = 1
                print(f"[ERROR] No matches detected ({functional_result['scan_time']:.3f}s)")

                # Show errors if any
                for error in functional_result['errors']:
                    print(f"   Error: {error}")
        else:
            self.test_results['summary']['syntax_failed'] = 1
            self.test_results['summary']['functional_failed'] = 1
            print(f"[ERROR] Syntax Error: {syntax_result['error_message']}")

        print(f"\n{'='*60}")
        print("SINGLE FILE TESTING COMPLETE")
        print(f"{'='*60}")
        print(f"[RESULTS]:")
        print(f"   File: {yara_file.name}")
        print(f"   Syntax: {'[PASSED]' if syntax_result['syntax_valid'] else '[FAILED]'}")
        print(f"   Functional: {'[PASSED]' if functional_result['successful_scans'] > 0 else '[FAILED]'}")

        return self.test_results

    def generate_test_report(self, report_file: Path):
        """Generate comprehensive test report"""
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# YARA Rules Comprehensive Test Report\n\n")
            f.write(f"**Generated on:** {datetime.now().isoformat()}\n")
            f.write(f"**Test Duration:** All rules tested systematically\n\n")

            # Summary
            f.write("## Test Summary\n\n")
            summary = self.test_results['summary']
            f.write(f"- **Total Rules:** {summary['total_rules']}\n")
            f.write(f"- **Syntax Passed:** {summary['syntax_passed']}\n")
            f.write(f"- **Syntax Failed:** {summary['syntax_failed']}\n")
            f.write(f"- **Functional Passed:** {summary['functional_passed']}\n")
            f.write(f"- **Functional Failed:** {summary['functional_failed']}\n")

            if summary['total_rules'] > 0:
                syntax_rate = (summary['syntax_passed'] / summary['total_rules']) * 100
                functional_rate = (summary['functional_passed'] / summary['total_rules']) * 100
                f.write(f"- **Syntax Success Rate:** {syntax_rate:.1f}%\n")
                f.write(f"- **Functional Success Rate:** {functional_rate:.1f}%\n")

            f.write("\n")

            # Syntax Test Results
            f.write("## Syntax Test Results\n\n")

            syntax_failures = [test for test in self.test_results['syntax_tests'] if not test['syntax_valid']]

            if syntax_failures:
                f.write(f"### Syntax Failures ({len(syntax_failures)})\n\n")
                for i, test in enumerate(syntax_failures, 1):
                    f.write(f"#### {i}. {Path(test['rule_file']).name}\n")
                    f.write(f"- **Error:** {test['error_message']}\n")
                    f.write(f"- **File Size:** {test['rule_size']} bytes\n\n")
            else:
                f.write("[SUCCESS] All YARA rules passed syntax validation!\n\n")

            # Functional Test Results
            f.write("## Functional Test Results\n\n")

            functional_passed = [test for test in self.test_results['functional_tests']
                               if test['successful_scans'] > 0]
            functional_failed = [test for test in self.test_results['functional_tests']
                                if test['successful_scans'] == 0]

            if functional_passed:
                f.write(f"### Functionally Successful Rules ({len(functional_passed)})\n\n")
                for test in functional_passed:
                    matches = {name: data for name, data in test['matches'].items()
                             if data.get('matched', False)}
                    f.write(f"- **{Path(test['rule_file']).name}**: {len(matches)} test files matched\n")
                    if matches:
                        for test_name, data in matches.items():
                            f.write(f"  - {test_name}: Match found\n")
                f.write("\n")

            if functional_failed:
                f.write(f"### Functionally Failed Rules ({len(functional_failed)})\n\n")
                for test in functional_failed:
                    f.write(f"#### {Path(test['rule_file']).name}\n")
                    f.write(f"- **Scans:** {test['successful_scans']}/{test['total_scans']} successful\n")
                    f.write(f"- **Scan Time:** {test['scan_time']:.3f}s\n")
                    if test['errors']:
                        f.write("- **Errors:**\n")
                        for error in test['errors']:
                            f.write(f"  - {error}\n")
                    f.write("\n")

            # Performance Analysis
            f.write("## Performance Analysis\n\n")

            syntax_times = [test['compilation_time'] for test in self.test_results['syntax_tests']
                          if test['compilation_time'] is not None]
            functional_times = [test['scan_time'] for test in self.test_results['functional_tests']]

            if syntax_times:
                f.write(f"### Compilation Performance\n")
                f.write(f"- **Average:** {sum(syntax_times)/len(syntax_times):.3f}s\n")
                f.write(f"- **Maximum:** {max(syntax_times):.3f}s\n")
                f.write(f"- **Minimum:** {min(syntax_times):.3f}s\n\n")

            if functional_times:
                f.write(f"### Scanning Performance\n")
                f.write(f"- **Average:** {sum(functional_times)/len(functional_times):.3f}s\n")
                f.write(f"- **Maximum:** {max(functional_times):.3f}s\n")
                f.write(f"- **Minimum:** {min(functional_times):.3f}s\n\n")

            # Recommendations
            f.write("## Recommendations\n\n")

            if syntax_failures:
                f.write("### Syntax Issues\n")
                f.write("- Review regex patterns for YARA compatibility\n")
                f.write("- Check for unsupported PCRE features\n")
                f.write("- Validate character class ranges\n")
                f.write("- Ensure proper escaping\n\n")

            if functional_failed:
                f.write("### Functional Issues\n")
                f.write("- Review version pattern matching logic\n")
                f.write("- Check test file content coverage\n")
                f.write("- Consider adding more diverse test cases\n")
                f.write("- Verify regex pattern accuracy\n\n")

            if not syntax_failures and not functional_failed:
                f.write("### [SUCCESS] Excellent Results\n")
                f.write("- All YARA rules are syntactically correct\n")
                f.write("- All rules successfully detected version patterns\n")
                f.write("- Rules are ready for production use\n\n")

        print(f"\nComprehensive test report generated: {report_file}")

    def generate_syntax_report(self, report_file: Path):
        """Generate syntax testing report"""
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# YARA Rules Syntax Test Report\n\n")
            f.write(f"**Generated on:** {datetime.now().isoformat()}\n")
            f.write(f"**Test Type:** Syntax Validation Only\n\n")

            # Summary
            f.write("## Syntax Test Summary\n\n")
            summary = self.test_results['summary']
            f.write(f"- **Total Rules:** {summary.get('total_rules', 0)}\n")
            f.write(f"- **Syntax Passed:** {summary.get('syntax_passed', 0)}\n")
            f.write(f"- **Syntax Failed:** {summary.get('syntax_failed', 0)}\n")

            if summary.get('total_rules', 0) > 0:
                syntax_rate = (summary.get('syntax_passed', 0) / summary.get('total_rules', 1)) * 100
                f.write(f"- **Syntax Success Rate:** {syntax_rate:.1f}%\n")

            f.write("\n")

            # Detailed Results
            f.write("## Detailed Syntax Results\n\n")

            if 'syntax_tests' in self.test_results and self.test_results['syntax_tests']:
                for i, test in enumerate(self.test_results['syntax_tests'], 1):
                    f.write(f"### {i}. {Path(test['rule_file']).name}\n\n")
                    f.write(f"- **Status:** {'✅ PASS' if test['syntax_valid'] else '❌ FAIL'}\n")
                    f.write(f"- **Compilation Time:** {test.get('compilation_time', 0):.3f}s\n")
                    f.write(f"- **File Size:** {test.get('rule_size', 0)} bytes\n")

                    if not test['syntax_valid']:
                        f.write(f"- **Error:** {test.get('error_message', 'Unknown error')}\n")

                        # Add recommendations
                        f.write("- **Recommendations:**\n")
                        f.write("  - Review regex patterns for YARA compatibility\n")
                        f.write("  - Check for unsupported PCRE features\n")
                        f.write("  - Validate character class ranges\n")
                        f.write("  - Ensure proper escaping\n")

                    f.write("\n")
            else:
                f.write("No syntax tests were performed.\n\n")

            # Performance Analysis
            if 'syntax_tests' in self.test_results and self.test_results['syntax_tests']:
                syntax_times = [test.get('compilation_time', 0) for test in self.test_results['syntax_tests']
                              if test.get('compilation_time') is not None]

                if syntax_times:
                    f.write("## Performance Analysis\n\n")
                    f.write("### Compilation Performance\n")
                    f.write(f"- **Average:** {sum(syntax_times)/len(syntax_times):.3f}s\n")
                    f.write(f"- **Maximum:** {max(syntax_times):.3f}s\n")
                    f.write(f"- **Minimum:** {min(syntax_times):.3f}s\n")
                    f.write(f"- **Total:** {sum(syntax_times):.3f}s\n\n")

            # Overall Recommendations
            f.write("## Overall Recommendations\n\n")
            failed_count = summary.get('syntax_failed', 0)
            passed_count = summary.get('syntax_passed', 0)

            if failed_count == 0:
                f.write("### 🎉 Excellent Results\n")
                f.write("- All YARA rules passed syntax validation\n")
                f.write("- Rules are ready for production use\n")
                f.write("- Proceed with functionality testing\n\n")
            else:
                f.write("### ⚠️ Syntax Issues Found\n")
                f.write(f"- {failed_count} rules have syntax issues that need fixing\n")
                f.write("- Review regex patterns for YARA compatibility\n")
                f.write("- Check character class ranges and escaping\n")
                f.write("- Test manually: bin/yarac64.exe rule.yara compiled.yc\n\n")

        print(f"Syntax test report generated: {report_file}")

    def generate_functionality_report(self, report_file: Path):
        """Generate functionality testing report"""
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# YARA Rules Functionality Test Report\n\n")
            f.write(f"**Generated on:** {datetime.now().isoformat()}\n")
            f.write(f"**Test Type:** Functionality Validation Only\n\n")

            # Summary
            f.write("## Functionality Test Summary\n\n")
            summary = self.test_results['summary']
            f.write(f"- **Total Rules:** {summary.get('total_rules', 0)}\n")
            f.write(f"- **Functional Passed:** {summary.get('functional_passed', 0)}\n")
            f.write(f"- **Functional Failed:** {summary.get('functional_failed', 0)}\n")

            if summary.get('total_rules', 0) > 0:
                functional_rate = (summary.get('functional_passed', 0) / summary.get('total_rules', 1)) * 100
                f.write(f"- **Functional Success Rate:** {functional_rate:.1f}%\n")

            f.write("\n")

            # Detailed Results
            f.write("## Detailed Functionality Results\n\n")

            if 'functional_tests' in self.test_results and self.test_results['functional_tests']:
                for i, test in enumerate(self.test_results['functional_tests'], 1):
                    f.write(f"### {i}. {Path(test['rule_file']).name}\n\n")
                    f.write(f"- **Status:** {'✅ PASS' if test['successful_scans'] > 0 else '❌ FAIL'}\n")
                    f.write(f"- **Successful Scans:** {test['successful_scans']}/{test['total_scans']}\n")
                    f.write(f"- **Scan Time:** {test.get('scan_time', 0):.3f}s\n")

                    # Show match details
                    matches = {name: data for name, data in test['matches'].items()
                              if data.get('matched', False)}

                    if matches:
                        f.write(f"- **Test Files Matched:** {len(matches)}/{len(test['matches'])}\n")
                        for test_name, match_data in matches.items():
                            f.write(f"  - ✅ {test_name}: {match_data.get('stdout', 'Match found')}\n")
                    else:
                        f.write("- **Test Files Matched:** 0/0\n")

                    if test['successful_scans'] == 0:
                        f.write("- **Recommendations:**\n")
                        f.write("  - Review version pattern accuracy\n")
                        f.write("  - Check test file contents\n")
                        f.write("  - Consider additional test cases\n")
                        if test.get('errors'):
                            f.write("  - Review errors below\n")

                    if test.get('errors'):
                        f.write("- **Errors:**\n")
                        for error in test['errors']:
                            f.write(f"  - {error}\n")

                    f.write("\n")
            else:
                f.write("No functionality tests were performed.\n\n")

            # Performance Analysis
            if 'functional_tests' in self.test_results and self.test_results['functional_tests']:
                scan_times = [test.get('scan_time', 0) for test in self.test_results['functional_tests']
                             if test.get('scan_time') is not None]

                if scan_times:
                    f.write("## Performance Analysis\n\n")
                    f.write("### Scanning Performance\n")
                    f.write(f"- **Average:** {sum(scan_times)/len(scan_times):.3f}s\n")
                    f.write(f"- **Maximum:** {max(scan_times):.3f}s\n")
                    f.write(f"- **Minimum:** {min(scan_times):.3f}s\n")
                    f.write(f"- **Total:** {sum(scan_times):.3f}s\n\n")

            # Overall Recommendations
            f.write("## Overall Recommendations\n\n")
            failed_count = summary.get('functional_failed', 0)
            passed_count = summary.get('functional_passed', 0)

            if failed_count == 0:
                f.write("### 🎉 Excellent Results\n")
                f.write("- All YARA rules successfully detected version patterns\n")
                f.write("- Rules are ready for production use\n")
                f.write("- Consider performance optimization for large-scale scanning\n\n")
            else:
                f.write("### ⚠️ Functionality Issues Found\n")
                f.write(f"- {failed_count} rules didn't match any test patterns\n")
                f.write("- Review version pattern accuracy\n")
                f.write("- Consider additional test cases\n")
                f.write("- Test against real-world samples\n\n")

        print(f"Functionality test report generated: {report_file}")


class RE2YARAVersionOnlyConverter:
    """Converts only Python VERSION_PATTERNS to YARA rules with focused traceability"""

    def __init__(self, source_dir: str, target_dir: str):
        self.source_dir = Path(source_dir)
        self.target_dir = Path(target_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)

        # Track conversion statistics with regex-difference focus
        self.conversion_stats = {
            'total_files': 0,
            'converted_files': 0,
            'failed_files': 0,
            'regex_difference_notes': [],  # Only records triggers of Python->YARA regex differences
            'conversion_time': datetime.now().isoformat()
        }

    def python_to_yara_regex(self, python_regex: str, source_info: Dict = None) -> str:
        """
        Convert Python regex to YARA regex format
        Enhanced with YARA compatibility fixes for unsupported PCRE features

        Args:
            python_regex: The original Python regex pattern
            source_info: Dict containing source file and pattern information for tracing

        Returns:
            YARA-compatible regex string
        """
        if not python_regex:
            return ""

        # Start with the original pattern
        yara_regex = python_regex
        original_regex = python_regex
        differences_triggered = []

        # Track YARA compatibility issues
        yara_compatibility_issues = []

        # Detect if this is a raw string pattern (contains actual backslash escape sequences)
        # In Python, r"\r?\n" will contain literal backslashes when extracted from AST
        # Check for actual escape sequences, not escaped dots like \.
        escape_sequences = {'\\r', '\\n', '\\t', '\\\\', '\\"', "\\'"}
        has_escape_sequence = any(seq in yara_regex for seq in escape_sequences)
        # Also check if the original python_regex starts with r" or r'
        original_is_raw = python_regex.startswith('r"') or python_regex.startswith("r'")
        is_raw_pattern = has_escape_sequence or original_is_raw

        # Extract the pattern content (remove surrounding quotes)
        yara_regex = yara_regex.strip('"\'')

        # Issue2 Enhancement #1: Remove %s from patterns (comprehensive removal)
        # Python patterns like r"%s version ([0-9]+\.[0-9]+)" should become "version ([0-9]+\.[0-9]+)"
        # Handles %s as prefix, suffix, middle, and multiple occurrences

        # Track original regex to detect changes
        original_regex = yara_regex

        # Remove %s and clean up adjacent spaces
        # Case 1: %s at start with following space -> remove both
        yara_regex = re.sub(r'^%s\s+', '', yara_regex)
        # Case 2: %s at end with preceding space -> remove both
        yara_regex = re.sub(r'\s+%s$', '', yara_regex)
        # Case 3: %s in middle with spaces around -> replace with single space
        yara_regex = re.sub(r'\s+%s\s+', ' ', yara_regex)
        # Case 4: %s in middle with no spaces -> remove %s
        yara_regex = re.sub(r'%s', '', yara_regex)

        # Clean up any double spaces that may have been created
        yara_regex = re.sub(r'\s{2,}', ' ', yara_regex)

        # Track if any %s was removed
        if original_regex != yara_regex:
            differences_triggered.append("removed_%s_comprehensive")

        # Issue2 Enhancement: Fix empty alternatives in pipe groups
        # Convert patterns like (| \r?\n) to (^|\r?\n) for proper regex matching
        original_regex_pipe = yara_regex

        # Fix empty alternatives in both capturing and non-capturing groups
        # Case 1: Non-capturing groups (?:|pattern) -> (^|pattern)
        yara_regex = re.sub(r'\(\?:\|\s*([^)]+)\)', r'(^\1)', yara_regex)
        # Case 2: Capturing groups (|pattern) -> (^|pattern)
        yara_regex = re.sub(r'\(\|\s*([^)]+)\)', r'(^\1)', yara_regex)
        # Case 3: Standalone empty alternatives not in groups (|pattern) -> (^|pattern)
        yara_regex = re.sub(r'\(\s*\|\s*([^)]*)\)', r'(^\1)', yara_regex)

        # Track if any pipe fix was applied
        if original_regex_pipe != yara_regex:
            differences_triggered.append("fixed_empty_alternatives")

        # Issue2 Enhancement #1.5: Process forward slash escape FIRST (before quantifier changes)
        # In Python regex, / is just a literal character
        # In YARA regex (when using /regex/ format), forward slashes need to be escaped: \/
        # Important: We only need single backslash in the final YARA pattern
        

        # Issue2 Enhancement #2: REMOVED - Keep ? quantifiers as-is
        # Issue2 requirement: Preserve ? quantifiers, do not convert to {0,1}
        # This also prevents {0,1} to ? conversion to maintain original ? quantifiers

        # Optimization: Replace non-greedy .*? with equivalent YARA pattern
        # Python's .*? matches any character except newlines, non-greedily
        # YARA equivalent: [^\x0A\x0D]* matches any character except \n and \r
        lazy_dot_pattern = r'\.\*\?'
        lazy_dot_matches = re.findall(lazy_dot_pattern, yara_regex)
        if lazy_dot_matches:
            # Use lambda function to avoid escape sequence issues in replacement
            yara_regex = re.sub(lazy_dot_pattern, lambda m: r'[^\x0A\x0D]*', yara_regex)
            differences_triggered.append(f"lazy_dot_replacement: {len(lazy_dot_matches)}")


        # Issue2 Enhancement #4: REMOVED - Preserve \- literals as-is
        # Issue2 requirement: Python RE literal \- should not be processed, preserve as literal
        # This maintains the original dash escape without any modification

        # Issue2 Enhancement #4.5: Optimize literal dash (\-) placement in character classes
        # Move ONLY literal backslash-dash (\-) characters to end of their immediate character classes to avoid ambiguity
        # In regex, [a-b] means range a to b, but [ab-] means literal a, b, or dash
        # We only process \- literals, not regular - characters, with proper nesting support

        # Pattern to match character classes and capture their content
        # This handles nested character classes by working with the innermost ones first
        char_class_pattern = r'\[([^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*)\]'

        def move_literal_dash_to_end_of_class(match):
            r"""Move literal \- to the end of its immediate containing character class"""
            full_content = match.group(1)  # Everything inside the outermost []

            # Process the content, moving \- to the end of this specific character class
            # Split by literal \- to find its position
            if r'\-' not in full_content:
                return match.group(0)  # No literal dash found

            # Split the content at literal \-
            parts = full_content.split(r'\-')
            if len(parts) <= 1:
                return match.group(0)  # No literal dash or malformed

            # Reconstruct without the literal dash
            content_without_dash = ''.join(parts)

            # Add the literal dash at the end of this character class
            optimized_content = content_without_dash + r'-'

            # Increment counter
            move_literal_dash_to_end_of_class.count += 1
            return f'[{optimized_content}]'

        def process_nested_character_classes(regex):
            r"""Process regex to move all literal \- to the end of their respective character classes"""
            # Use re.sub repeatedly until no more changes are made
            # This handles nested character classes by processing innermost first
            prev_result = ""
            current_result = regex

            while current_result != prev_result:
                prev_result = current_result
                # Find all character classes and process each one
                current_result = re.sub(char_class_pattern, move_literal_dash_to_end_of_class, current_result)

            return current_result

        # Initialize counter for the nested function
        move_literal_dash_to_end_of_class.count = 0

        # Apply literal dash placement optimization with proper nesting support
        yara_regex = process_nested_character_classes(yara_regex)

        if move_literal_dash_to_end_of_class.count > 0:
            differences_triggered.append(f"optimized_literal_dash_placement:{move_literal_dash_to_end_of_class.count}")



        # YARA Compatibility Enhancement: Check for unsupported PCRE features
        # 1. Check for non-capturing groups (?:...)
        non_capturing_group_pattern = r'\(\?:'
        non_capturing_matches = re.finditer(non_capturing_group_pattern, yara_regex)
        for match in non_capturing_matches:
            yara_compatibility_issues.append({
                'type': 'non_capturing_group',
                'position': match.start(),
                'match': match.group(),
                'issue': 'YARA does not support non-capturing groups (?:)',
                'solution': 'Convert to regular capturing group (...)'
            })

        # 2. Check for problematic ? quantifiers that may cause performance issues
        # Look for standalone ? quantifiers that could cause backtracking
        problematic_question_pattern = r'(?<!\\)[?](?![*+?{}])'
        question_matches = re.finditer(problematic_question_pattern, yara_regex)
        for match in question_matches:
            yara_compatibility_issues.append({
                'type': 'problematic_question_quantifier',
                'position': match.start(),
                'match': match.group(),
                'issue': '? quantifier may cause performance issues in YARA',
                'solution': 'Replace with {0,1} or use alternative patterns'
            })

        # 3. Check for other unsupported PCRE features
        unsupported_patterns = [
            (r'\(\?\(', 'conditional_subpattern', 'YARA does not support conditional subpatterns (?(...))'),
            (r'\(\?\?.*\)', 'verbal_expression', 'YARA does not support verb-like expressions (??...)'),
            (r'\(\?[>!=:]', 'lookaround_assertion', 'YARA does not support lookaround assertions'),
            (r'\(\?[imsxU]*-[imsxU]*:*\)', 'inline_modifiers', 'YARA has limited inline modifier support')
        ]

        for pattern, issue_type, description in unsupported_patterns:
            matches = re.finditer(pattern, yara_regex)
            for match in matches:
                yara_compatibility_issues.append({
                    'type': issue_type,
                    'position': match.start(),
                    'match': match.group(),
                    'issue': description,
                    'solution': 'Remove or restructure using YARA-compatible syntax'
                })

        # For YARA regex, we need to ensure escape sequences work correctly
        if not is_raw_pattern:
            # Process common Python escape sequences for regular strings
            yara_regex = yara_regex.replace('\\r', '\r')
            yara_regex = yara_regex.replace('\\n', '\n')
            yara_regex = yara_regex.replace('\\t', '\t')
            yara_regex = yara_regex.replace('\\"', '"')
            yara_regex = yara_regex.replace("\\'", "'")
            yara_regex = yara_regex.replace('\\\\', '\\')

        # Apply YARA compatibility fixes
        # 1. Replace non-capturing groups with regular groups
        non_capturing_count = len(re.findall(non_capturing_group_pattern, yara_regex))
        if non_capturing_count > 0:
            yara_regex = re.sub(non_capturing_group_pattern, '(', yara_regex)
            differences_triggered.append(f"non_capturing_groups_replaced: {non_capturing_count}")

        # 2. REMOVED - Do not replace ? quantifiers with {0,1}
        # Issue2 requirement: Preserve ? quantifiers as-is, no optimization needed

        # 3. Special handling for patterns starting with \r?\n - use (^|\r?\n) for better flexibility
        if yara_regex.startswith(r'\r?\n'):
            # Replace leading \r?\n with (^|\r?\n) to match either line start or preceding newline
            yara_regex = yara_regex.replace(r'\r?\n', r'(^|\r?\n)', 1)
            differences_triggered.append("newline_to_group_anchor_fix")

        # 4. Remove other unsupported PCRE features
        for pattern, _, _ in unsupported_patterns:
            if re.search(pattern, yara_regex):
                # For now, we'll remove these features and add a note
                yara_regex = re.sub(pattern, '', yara_regex)
                differences_triggered.append(f"unsupported_pcre_feature_removed: {pattern}")

        # Valid YARA regex escape characters that should remain as \x
        valid_yara_escapes = {'r', 'n', 't', 'f', 'v', 'a', 'b', 'd', 'D', 's', 'S', 'w', 'W',
                             'x', 'u', 'U', 'l', 'L', 'h', 'H', 'R', 'V', 'k', 'K', 'p', 'P',
                             'g', 'G', 'A', 'Z', 'B', 'E', 'N', 'O', 'Q', 'C', 'I', 'J'}

        result = []
        i = 0
        while i < len(yara_regex):
            if yara_regex[i] == '\\':
                # Check if this is part of a valid regex escape sequence
                if i + 1 < len(yara_regex):
                    next_char = yara_regex[i + 1]
                    if next_char in valid_yara_escapes:
                        # Valid regex escape - keep as single backslash
                        result.append('\\' + next_char)
                        i += 2
                        continue
                    elif next_char in '?.*+[]{}()|^$\\':
                        # Special regex characters that can be escaped
                        result.append('\\' + next_char)
                        i += 2
                        continue
                # Lone backslash - double escape it for YARA
                result.append('\\\\')
                i += 1
            else:
                result.append(yara_regex[i])
                i += 1

        yara_regex = ''.join(result)

        # Issue2 Enhancement #5: Fix character range issues
        # Find and fix invalid character ranges like [z-a], [a-Z], [9-0] etc.
        # Fix simple reversed ranges
        range_fixes = [
            (r'\[([^\]]*z-a[^\]]*)\]', r'[\\1a-z\\2]'),  # z-a -> a-z
            (r'\[([^\]]*a-Z[^\]]*)\]', r'[\\1A-Z\\2]'),  # a-Z -> A-Z
            (r'\[([^\]]*9-0[^\]]*)\]', r'[\\10-9\\2]'),  # 9-0 -> 0-9
            (r'\[([^\]]*A-a[^\]]*)\]', r'[\\1a-z\\2]'),  # A-a -> a-z
        ]

        fixed_ranges = 0
        for pattern, replacement in range_fixes:
            matches = re.findall(pattern, yara_regex)
            if matches:
                yara_regex = re.sub(pattern, replacement, yara_regex)
                fixed_ranges += len(matches)

        if fixed_ranges > 0:
            differences_triggered.append(f"fixed_character_ranges:{fixed_ranges}")

        # Issue2 Enhancement #6: Fix unmatched character class brackets
        # Count unmatched opening and closing brackets
        open_brackets = len(re.findall(r'(?<!\\)\[', yara_regex))
        close_brackets = len(re.findall(r'(?<!\\)\]', yara_regex))

        if open_brackets != close_brackets:
            if open_brackets > close_brackets:
                # Add missing closing brackets
                missing = open_brackets - close_brackets
                yara_regex += ']' * missing
                differences_triggered.append(f"added_missing_closing_brackets:{missing}")
            elif close_brackets > open_brackets:
                # Remove extra closing brackets
                extra = close_brackets - open_brackets
                yara_regex = re.sub(r'(?<!\\)\]', '', yara_regex, count=extra)
                differences_triggered.append(f"removed_extra_closing_brackets:{extra}")

        # Check for major Python->YARA regex differences
        # Only record if these features are present

        # Named groups check
        named_groups = re.findall(r'\(\?P<[^>]+>', yara_regex)
        if named_groups:
            yara_regex = re.sub(r'\(\?P<[^>]+>', '(?:', yara_regex)
            differences_triggered.append(f"named_groups: {len(named_groups)}")

        # Conditional groups check
        conditional_pattern = r'\(\?\([^)]+\)[^)]*\)'
        conditional_groups = re.findall(conditional_pattern, yara_regex)
        if conditional_groups:
            yara_regex = re.sub(conditional_pattern, '', yara_regex)
            differences_triggered.append(f"conditional_groups: {len(conditional_groups)}")

        # Lookaheads/lookbehinds check
        lookahead_patterns = [
            (r'\(\?=[^)]*\)', 'positive_lookahead'),
            (r'\(\?![^)]*\)', 'negative_lookahead'),
            (r'\(\?<=[^)]*\)', 'positive_lookbehind'),
            (r'\(\?<![^)]*\)', 'negative_lookbehind')
        ]

        total_lookarounds = 0
        for pattern, name in lookahead_patterns:
            matches = re.findall(pattern, yara_regex)
            if matches:
                yara_regex = re.sub(pattern, '', yara_regex)
                total_lookarounds += len(matches)

        if total_lookarounds > 0:
            differences_triggered.append(f"lookaheads_lookbehinds: {total_lookarounds}")

        # Possessive quantifiers check
        possessive_counts = {}
        for quantifier in ['++', '*+', '?+']:
            count = len(re.findall(re.escape(quantifier), yara_regex))
            if count > 0:
                possessive_counts[quantifier] = count
                yara_regex = yara_regex.replace(quantifier, quantifier[0])

        if possessive_counts:
            differences_triggered.append(f"possessive_quantifiers: {dict(possessive_counts)}")

        # Issue2 Enhancement #7: Handle trailing spaces in YARA regex patterns
        # YARA /regex/ format can't have trailing spaces as they're interpreted as YARA syntax
        # if yara_regex.endswith(' '):
        #     # Replace trailing space with space character class [ ]
        #     # This is the most YARA-compatible way to match trailing spaces
        #     yara_regex = yara_regex[:-1] + '[ ]'
        #     # differences_triggered.append("trailing_space_to_char_class")

        # Only record if differences were triggered
        if differences_triggered:
            note = {
                'source_file': source_info.get('file', 'unknown') if source_info else 'unknown',
                'pattern_type': 'VERSION_PATTERNS',
                'pattern_index': source_info.get('pattern_index', 0) if source_info else 0,
                'original_pattern': original_regex[:200] + ('...' if len(original_regex) > 200 else ''),
                'converted_pattern': yara_regex[:200] + ('...' if len(yara_regex) > 200 else ''),
                'differences_triggered': differences_triggered,
                'conversion_timestamp': datetime.now().isoformat()
            }
            self.conversion_stats['regex_difference_notes'].append(note)

        # Also record YARA compatibility issues if found
        if yara_compatibility_issues:
            compatibility_note = {
                'source_file': source_info.get('file', 'unknown') if source_info else 'unknown',
                'pattern_type': 'VERSION_PATTERNS',
                'pattern_index': source_info.get('pattern_index', 0) if source_info else 0,
                'original_pattern': original_regex[:200] + ('...' if len(original_regex) > 200 else ''),
                'converted_pattern': yara_regex[:200] + ('...' if len(yara_regex) > 200 else ''),
                'yara_compatibility_issues': yara_compatibility_issues,
                'conversion_timestamp': datetime.now().isoformat()
            }
            self.conversion_stats['regex_difference_notes'].append(compatibility_note)

       
        # Count all forward slashes (both escaped and unescaped) more comprehensively
        escaped_slashes = len(re.findall(r'\\/', yara_regex))  # Count \/
        unescaped_slashes = len(re.findall(r'(?<!\\)/', yara_regex))  # Count / not preceded by \
        all_slashes = escaped_slashes + unescaped_slashes

        if all_slashes > 0:
            # Unified approach: First normalize everything to /, then escape all
            # This handles both / and \/ correctly
            yara_regex = yara_regex.replace(r'\\/', '/')  # Convert \/ back to /
            yara_regex = yara_regex.replace('/', r'\/')    # Escape all / to \/
            differences_triggered.append(f"escaped_all_forward_slashes:{all_slashes}")


        return yara_regex

    def extract_class_info(self, file_path: Path, args=None) -> Optional[Dict]:
        """Extract VERSION_PATTERNS only from Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Parse the Python file
            tree = ast.parse(content)

            # Find the Checker class
            checker_class = None
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name.endswith('Checker'):
                    checker_class = node
                    break

            if not checker_class:
                return None

            # Extract only VERSION_PATTERNS
            class_info = {
                'name': checker_class.name,
                'filename': file_path.stem,
                'version_patterns': [],
                'vendor_product': []
            }

            if args.verbose:
                print(f"[DEBUG] Found class {checker_class.name} in {file_path.name}")

            for item in checker_class.body:
                # Handle both regular assignments (ast.Assign) and annotated assignments (ast.AnnAssign)
                if isinstance(item, ast.Assign):
                    # Regular assignment: e.g., VERSION_PATTERNS = [...]
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            attr_name = target.id
                            self._process_attribute(attr_name, item.value, class_info, args)

                elif isinstance(item, ast.AnnAssign):
                    # Annotated assignment: e.g., VERSION_PATTERNS: list[str] = [...]
                    if hasattr(item, 'target') and isinstance(item.target, ast.Name):
                        attr_name = item.target.id
                        self._process_attribute(attr_name, item.value, class_info, args)

            return class_info

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None

    def _process_attribute(self, attr_name: str, attr_value, class_info: Dict, args) -> None:
        """
        Process a single attribute from AST (works for both ast.Assign and ast.AnnAssign)

        Args:
            attr_name: Name of the attribute (e.g., 'VERSION_PATTERNS')
            attr_value: AST value node containing the attribute data
            class_info: Dictionary to store extracted information
            args: Command line arguments for debugging
        """
        if attr_name == 'VERSION_PATTERNS':
            if args.verbose:
                print(f"[DEBUG] Found VERSION_PATTERNS in {class_info['filename']}")
                print(f"[DEBUG] Attribute value type: {type(attr_value).__name__}")
                print(f"[DEBUG] Is ast.List: {isinstance(attr_value, ast.List)}")

                # Debug: Check for annotation type compatibility
                if hasattr(attr_value, 'annotation'):
                    print(f"[DEBUG] Has annotation: {type(attr_value.annotation).__name__}")

            if isinstance(attr_value, ast.List):
                if args.verbose:
                    print(f"[DEBUG] Processing {len(attr_value.elts)} elements in VERSION_PATTERNS")

                for i, elt in enumerate(attr_value.elts):
                    if args.verbose:
                        print(f"[DEBUG] Element {i}: {type(elt).__name__}")

                    if hasattr(elt, 'value'):  # ast.Constant for Python >= 3.8
                        if args.verbose:
                            print(f"[DEBUG] Adding version pattern (ast.Constant): {repr(elt.value)}")
                        class_info['version_patterns'].append(elt.value)
                    elif hasattr(elt, 's'):  # ast.Str for Python < 3.8 (deprecated)
                        if args.verbose:
                            print(f"[DEBUG] Adding version pattern (ast.Str): {repr(elt.s)}")
                        class_info['version_patterns'].append(elt.s)
                    else:
                        if args.verbose:
                            print(f"[DEBUG] Element {i} has no 'value' or 's' attribute")
                            print(f"[DEBUG] Element dump: {ast.dump(elt)}")
            else:
                if args.verbose:
                    print(f"[DEBUG] VERSION_PATTERNS is not ast.List, type: {type(attr_value).__name__}")
                    print(f"[DEBUG] AST dump: {ast.dump(attr_value)}")

        elif attr_name == 'VENDOR_PRODUCT':
            if isinstance(attr_value, ast.List):
                for elt in attr_value.elts:
                    if isinstance(elt, ast.Tuple):
                        vendor = product = ""
                        if len(elt.elts) >= 2:
                            if hasattr(elt.elts[0], 'value'):
                                vendor = elt.elts[0].value
                            elif hasattr(elt.elts[0], 's'):  # deprecated
                                vendor = elt.elts[0].s
                            else:
                                vendor = str(elt.elts[0])

                            if hasattr(elt.elts[1], 'value'):
                                product = elt.elts[1].value
                            elif hasattr(elt.elts[1], 's'):  # deprecated
                                product = elt.elts[1].s
                            else:
                                product = str(elt.elts[1])

                            class_info['vendor_product'].append((vendor, product))

    def generate_yara_rule(self, class_info: Dict) -> str:
        """
        Generate YARA rule focused only on VERSION_PATTERNS
        """
        # Fix rule naming to avoid conflicts and ensure valid YARA identifiers
        rule_name = f"{class_info['filename']}_version_only"
        rule_name = rule_name.replace('.', '_').replace('-', '_').replace(' ', '_')

        # Ensure rule name starts with letter or underscore (YARA requirement)
        if rule_name and rule_name[0].isdigit():
            rule_name = f"_{rule_name}"

        software_name = ' '.join(word.capitalize() for word in rule_name.replace('_version_only', '').split('_'))

        # Extract description from docstring or generate one
        description = f"Version detection rule for {software_name}"

        # Generate strings section - only version patterns
        strings = []
        version_count = 0

        for i, pattern in enumerate(class_info['version_patterns']):
            if pattern.strip():
                source_info = {
                    'file': class_info['filename'],
                    'pattern_type': 'VERSION_PATTERNS',
                    'pattern_index': i
                }
                yara_pattern = self.python_to_yara_regex(pattern, source_info)
                if yara_pattern:
                    # Fix: Use string concatenation instead of f-string to avoid double escaping
                    # In f-strings, backslashes get escaped again, causing \/ to become \\//
                    yara_string = r'        $version' + str(version_count) + ' = /' + yara_pattern + '/ nocase ascii wide'
                    strings.append(yara_string)
                    version_count += 1

        # Generate condition - Issue2 compliant YARA syntax
        if version_count > 0:
            # Issue2 requirement: any of must be followed by a set/list of string identifiers
            if version_count == 1:
                condition = "$version0"
            else:
                # Issue2 requirement: any of ($version0, $version1, ...) not boolean expression
                # $version0 or $version1 is a boolean expression, not a set
                condition = f"any of them"  # Most concise and Issue2 compliant
        else:
            condition = "false  // No valid version patterns found"

        # Fix trailing whitespace in YARA regex patterns
        # YARA /regex/ format can't have trailing spaces as they're interpreted as YARA syntax
        for i in range(len(strings)):
            if strings[i].startswith('        $version'):
                # Check if pattern ends with trailing space that breaks YARA syntax
                if strings[i].endswith('/ nocase ascii wide'):
                    # Extract the pattern between /.../
                    parts = strings[i].split('/')
                    if len(parts) >= 3:
                        pattern = parts[1]
                        # Check if pattern has trailing space
                        if pattern.endswith(' '):
                            # FIXED: Remove trailing space processing - keep original space as-is
                            # YARA can handle trailing spaces in /pattern/ format
                            pass
                            strings[i] = f'        $version{i} = /{pattern}/ nocase ascii wide'

        # Build the complete YARA rule
        yara_rule = f'''rule {rule_name}
{{
    meta:
        software_name = "{software_name}"
        open_source = true
        website = "Generated from Python VERSION_PATTERNS only"
        description = "{description}"
        generated_from = "source_python_re/{class_info['filename']}.py"
        conversion_mode = "version_only"
        vendor_product = "{', '.join([f'{v}:{p.replace(r"\/","/")}' for v, p in class_info['vendor_product']])}"
    strings:
{chr(10).join(strings) if strings else "        // No version patterns found"}
    condition:
        {condition}
}}'''

        return yara_rule

    def convert_file(self, source_file: Path, args=None) -> bool:
        """
        Convert a single Python RE file to VERSION_PATTERNS-only YARA rule
        """
        file_conversion_start = len(self.conversion_stats['regex_difference_notes'])
        source_filename = source_file.name

        try:
            # Track file conversion start
            conversion_start = datetime.now().isoformat()

            class_info = self.extract_class_info(source_file, args)
            if not class_info:
                # Record extraction failure
                failure_note = {
                    'type': 'extraction_failure',
                    'source_file': source_filename,
                    'error': 'Failed to extract VERSION_PATTERNS from checker class',
                    'timestamp': conversion_start
                }
                self.conversion_stats['regex_difference_notes'].append(failure_note)
                return False

            # Check if we have version patterns
            if not class_info['version_patterns']:
                no_version_note = {
                    'type': 'no_version_patterns',
                    'source_file': source_filename,
                    'timestamp': conversion_start
                }
                self.conversion_stats['regex_difference_notes'].append(no_version_note)
                # Still create the rule (will have "false" condition)

            yara_rule = self.generate_yara_rule(class_info)

            target_file = self.target_dir / f"{source_file.stem}_version_only.yara"
            with open(target_file, 'w', encoding='utf-8') as f:
                f.write(yara_rule)

            # Count regex differences for this file
            file_regex_differences = len(self.conversion_stats['regex_difference_notes']) - file_conversion_start

            # Record conversion success
            success_note = {
                'type': 'version_conversion_success',
                'source_file': source_filename,
                'target_file': target_file.name,
                'version_patterns_found': len(class_info['version_patterns']),
                'regex_differences_triggered': file_regex_differences,
                'rule_size': len(yara_rule),
                'timestamp': datetime.now().isoformat()
            }
            self.conversion_stats['regex_difference_notes'].append(success_note)

            print(f"Converted: {source_file.name} -> {target_file.name} ({file_regex_differences} regex differences)")
            return True

        except Exception as e:
            # Record conversion failure
            import traceback
            failure_note = {
                'type': 'conversion_failure',
                'source_file': source_filename,
                'error': str(e),
                'traceback': traceback.format_exc(),
                'timestamp': datetime.now().isoformat()
            }
            self.conversion_stats['regex_difference_notes'].append(failure_note)

            print(f"Failed to convert {source_file.name}: {e}")
            return False

    def convert_all(self, args=None):
        """Convert all Python RE files to VERSION_PATTERNS-only YARA rules"""
        python_files = list(self.source_dir.glob("*.py"))
        python_files = [f for f in python_files if f.name != "__init__.py"]

        self.conversion_stats['total_files'] = len(python_files)

        print(f"Starting VERSION_PATTERNS-only conversion of {len(python_files)} Python RE files...")
        print("Only regex differences will be tracked in traceability reports.")

        for py_file in python_files:
            if self.convert_file(py_file, args):
                self.conversion_stats['converted_files'] += 1
            else:
                self.conversion_stats['failed_files'] += 1

        print(f"\nConversion complete!")
        print(f"Total files: {self.conversion_stats['total_files']}")
        print(f"Successfully converted: {self.conversion_stats['converted_files']}")
        print(f"Failed: {self.conversion_stats['failed_files']}")
        print(f"Regex difference notes: {len(self.conversion_stats['regex_difference_notes'])}")

    def generate_regex_difference_report(self):
        """
        Generate focused report on regex differences only
        Place reports in the project root directory (outside target folder)
        """
        # Place report files in the project root directory (same level as source directory)
        project_root = self.source_dir.parent
        report_file = project_root / "regex_difference_report.md"
        detailed_trace_file = project_root / "regex_difference_trace.json"

        # Analyze regex differences and YARA compatibility issues
        regex_difference_types = {}
        yara_compatibility_types = {}
        files_with_differences = set()
        files_with_compatibility_issues = set()
        total_differences = 0
        total_compatibility_issues = 0

        for note in self.conversion_stats['regex_difference_notes']:
            if isinstance(note, dict):
                note_type = note.get('type', 'unknown')

                if note_type == 'extraction_failure' or note_type == 'conversion_failure':
                    regex_difference_types[note_type] = regex_difference_types.get(note_type, 0) + 1
                elif 'differences_triggered' in note:
                    files_with_differences.add(note['source_file'])
                    total_differences += 1

                    # Count specific difference types
                    for diff_type in note['differences_triggered']:
                        if ':' in diff_type:
                            category = diff_type.split(':')[0]
                            count = int(diff_type.split(':')[1]) if len(diff_type.split(':')) > 1 else 1
                            regex_difference_types[category] = regex_difference_types.get(category, 0) + count

                elif 'yara_compatibility_issues' in note:
                    files_with_compatibility_issues.add(note['source_file'])
                    total_compatibility_issues += len(note['yara_compatibility_issues'])

                    # Count specific YARA compatibility issue types
                    for issue in note['yara_compatibility_issues']:
                        issue_type = issue.get('type', 'unknown')
                        yara_compatibility_types[issue_type] = yara_compatibility_types.get(issue_type, 0) + 1

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# Python RE to YARA Regex Difference and Compatibility Report\n\n")
            f.write(f"**Generated on:** {datetime.now().isoformat()}\n")
            f.write(f"**Conversion Mode:** VERSION_PATTERNS-only with YARA Compatibility Enhancement\n\n")

            f.write("## Summary\n\n")
            f.write(f"- Total files processed: {self.conversion_stats['total_files']}\n")
            f.write(f"- Successfully converted: {self.conversion_stats['converted_files']}\n")
            f.write(f"- Failed conversions: {self.conversion_stats['failed_files']}\n")
            f.write(f"- Files with regex differences: {len(files_with_differences)}\n")
            f.write(f"- Files with YARA compatibility issues: {len(files_with_compatibility_issues)}\n")
            f.write(f"- Total regex difference entries: {total_differences}\n")
            f.write(f"- Total YARA compatibility issues: {total_compatibility_issues}\n")
            f.write(f"- Total traceability entries: {len(self.conversion_stats['regex_difference_notes'])}\n\n")

            f.write("## Regex Difference Types\n\n")
            if regex_difference_types:
                for diff_type, count in sorted(regex_difference_types.items()):
                    f.write(f"- {diff_type}: {count}\n")
            else:
                f.write("No regex differences detected.\n")
            f.write("\n")

            f.write("## YARA Compatibility Issues\n\n")
            if yara_compatibility_types:
                for issue_type, count in sorted(yara_compatibility_types.items()):
                    f.write(f"- {issue_type}: {count}\n")
                    # Add description for common issues
                    if issue_type == 'non_capturing_group':
                        f.write("  - Issue: YARA does not support non-capturing groups `(?:...)`\n")
                        f.write("  - Solution: Convert to regular capturing groups `(...)`\n")
                    elif issue_type == 'problematic_question_quantifier':
                        f.write("  - Issue: `?` quantifier may cause performance issues\n")
                        f.write("  - Solution: Replace with `{0,1}` or use alternative patterns\n")
                    elif issue_type == 'conditional_subpattern':
                        f.write("  - Issue: YARA does not support conditional subpatterns `?(...)`\n")
                        f.write("  - Solution: Remove or restructure using YARA-compatible syntax\n")
                    elif issue_type == 'lookaround_assertion':
                        f.write("  - Issue: YARA does not support lookaround assertions `?<!...>`\n")
                        f.write("  - Solution: Remove or use alternative matching strategies\n")
                    elif issue_type == 'verb_like_expression':
                        f.write("  - Issue: YARA does not support verb-like expressions `??...`\n")
                        f.write("  - Solution: Remove or simplify pattern\n")
                    elif issue_type == 'inline_modifiers':
                        f.write("  - Issue: YARA has limited inline modifier support\n")
                        f.write("  - Solution: Use global modifiers or remove unsupported ones\n")
                    f.write("\n")
            else:
                f.write("No YARA compatibility issues detected.\n")
            f.write("\n")

            # Group differences by file
            file_differences = {}
            for note in self.conversion_stats['regex_difference_notes']:
                if isinstance(note, dict) and 'differences_triggered' in note:
                    file_name = note['source_file']
                    if file_name not in file_differences:
                        file_differences[file_name] = []
                    file_differences[file_name].append(note)

            f.write("## Files with Regex Differences\n\n")
            if file_differences:
                for file_name, notes in sorted(file_differences.items()):
                    f.write(f"### {file_name}\n\n")

                    for note in notes:
                        f.write(f"**Pattern {note['pattern_index']}:**\n")
                        f.write(f"- **Original:** `{note['original_pattern']}`\n")
                        f.write(f"- **Converted:** `{note['converted_pattern']}`\n")
                        f.write(f"- **Differences:** {', '.join(note['differences_triggered'])}\n")
                        f.write(f"- **Timestamp:** {note['conversion_timestamp']}\n\n")
                    f.write("---\n\n")
            else:
                f.write("No files triggered regex differences.\n\n")

            f.write("## Conversion Notes\n\n")
            other_notes = [note for note in self.conversion_stats['regex_difference_notes']
                          if isinstance(note, dict) and 'differences_triggered' not in note]

            if other_notes:
                for note in other_notes:
                    f.write(f"### {note.get('type', 'unknown')}: {note.get('source_file', 'unknown')}\n\n")
                    if 'error' in note:
                        f.write(f"**Error:** {note['error']}\n\n")
                    if 'version_patterns_found' in note:
                        f.write(f"**Version Patterns Found:** {note['version_patterns_found']}\n\n")
                    if 'regex_differences_triggered' in note:
                        f.write(f"**Regex Differences:** {note.get('differences_triggered', [])}\n\n")
                    f.write(f"**Timestamp:** {note.get('timestamp', note.get('conversion_timestamp', 'unknown'))}\n\n")
                    f.write("---\n\n")

        # Generate detailed JSON trace
        with open(detailed_trace_file, 'w', encoding='utf-8') as f:
            detailed_report = {
                'metadata': {
                    'generated_on': datetime.now().isoformat(),
                    'conversion_mode': 'version_only_with_yara_compatibility',
                    'total_files': self.conversion_stats['total_files'],
                    'converted_files': self.conversion_stats['converted_files'],
                    'failed_files': self.conversion_stats['failed_files'],
                    'total_differences': total_differences,
                    'total_compatibility_issues': total_compatibility_issues,
                    'files_with_differences': len(files_with_differences),
                    'files_with_compatibility_issues': len(files_with_compatibility_issues)
                },
                'regex_difference_analysis': {
                    'difference_types': regex_difference_types,
                    'yara_compatibility_types': yara_compatibility_types,
                    'total_trace_entries': len(self.conversion_stats['regex_difference_notes'])
                },
                'files_with_differences': list(files_with_differences),
                'files_with_compatibility_issues': list(files_with_compatibility_issues),
                'complete_trace': self.conversion_stats['regex_difference_notes']
            }
            json.dump(detailed_report, f, indent=2, ensure_ascii=False)

        print(f"\nRegex difference report generated: {report_file}")
        print(f"Detailed trace report generated: {detailed_trace_file}")
        print(f"Reports are now placed in project root directory for easy access")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Convert Python VERSION_PATTERNS to YARA rules with independent testing subcommands",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic conversion (default behavior)
  %(prog)s

  # Syntax testing subcommands
  %(prog)s test-syntax                    # Test syntax of all YARA files
  %(prog)s test-syntax file.yara          # Test syntax of specific file
  %(prog)s test-syntax --all              # Test syntax of all YARA files (explicit)

  # Functionality testing subcommands
  %(prog)s test-functionality             # Test functionality of all YARA files
  %(prog)s test-functionality file.yara   # Test functionality of specific file
  %(prog)s test-functionality --all       # Test functionality of all YARA files (explicit)

  # Conversion with options
  %(prog)s --source-dir input/ --target-dir output/
  %(prog)s --verbose
        """
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Default conversion command (no subcommand)
    parser.set_defaults(command='convert')

    # Syntax testing subcommand
    syntax_parser = subparsers.add_parser(
        'test-syntax',
        help='Test YARA rule syntax only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s test-syntax                           # Test syntax of all YARA files
  %(prog)s test-syntax target_yara_version_only/curl_version_only.yara  # Test specific file
  %(prog)s test-syntax --all                     # Test all YARA files explicitly
        """
    )
    syntax_parser.add_argument(
        'file',
        nargs='?',
        help='Specific YARA file to test (optional, defaults to all files)'
    )
    syntax_parser.add_argument(
        '--all',
        action='store_true',
        help='Test all YARA files in target directory (default behavior when no file specified)'
    )

    # Functionality testing subcommand
    functionality_parser = subparsers.add_parser(
        'test-functionality',
        help='Test YARA rule functionality only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s test-functionality                    # Test functionality of all YARA files
  %(prog)s test-functionality target_yara_version_only/curl_version_only.yara  # Test specific file
  %(prog)s test-functionality --all              # Test all YARA files explicitly
        """
    )
    functionality_parser.add_argument(
        'file',
        nargs='?',
        help='Specific YARA file to test (optional, defaults to all files)'
    )
    functionality_parser.add_argument(
        '--all',
        action='store_true',
        help='Test all YARA files in target directory (default behavior when no file specified)'
    )

    # Common options for all commands
    parser.add_argument(
        '--source-dir', '-s',
        default="source_python_re",
        help='Source directory containing Python checker files (default: source_python_re)'
    )

    parser.add_argument(
        '--target-dir', '-t',
        default="target_yara_version_only",
        help='Target directory for YARA rules (default: target_yara_version_only)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output with detailed progress information'
    )

    parser.add_argument(
        '--yara-binary',
        default="bin/yara64.exe",
        help='Path to YARA binary (default: bin/yara64.exe)'
    )

    parser.add_argument(
        '--yarac-binary',
        default="bin/yarac64.exe",
        help='Path to YARA compiler binary (default: bin/yarac64.exe)'
    )

    # Backward compatibility: support old --test argument for transition
    parser.add_argument(
        '--test',
        nargs='?',
        const='__all__',
        default=None,
        help=argparse.SUPPRESS + ' (Deprecated: Use test-syntax or test-functionality subcommands)'
    )

    return parser.parse_args()


def main():
    """Main function to run the version-only converter with independent testing subcommands"""
    # Parse command line arguments
    args = parse_arguments()

    source_dir = args.source_dir
    target_dir = args.target_dir
    command = getattr(args, 'command', 'convert')

    if args.verbose:
        print(f"Configuration:")
        print(f"   Command: {command}")
        print(f"   Source Directory: {source_dir}")
        print(f"   Target Directory: {target_dir}")
        print(f"   YARA Binary: {args.yara_binary}")
        print(f"   YARA Compiler: {args.yarac_binary}")
        print(f"   Verbose Mode: {'Enabled' if args.verbose else 'Disabled'}")
        print(f"{'='*60}")

    # Handle backward compatibility for deprecated --test argument
    if hasattr(args, 'test') and args.test:
        print(f"[WARNING] --test argument is deprecated. Use 'test-syntax' or 'test-functionality' subcommands instead.")
        command = 'test'  # Legacy mode

    # Handle different commands
    if command == 'test-syntax':
        handle_syntax_testing(args)
    elif command == 'test-functionality':
        handle_functionality_testing(args)
    elif command == 'test':  # Legacy backward compatibility
        handle_legacy_testing(args)
    else:  # Default conversion
        handle_conversion(args)


def handle_syntax_testing(args):
    """Handle syntax testing subcommand"""
    print(f"SYNTAX TESTING MODE - testing YARA rule syntax only")

    # Determine test target
    test_file = None
    test_all = True

    if hasattr(args, 'file') and args.file:
        test_file = Path(args.file)
        test_all = False
    elif hasattr(args, 'all') and args.all:
        test_all = True

    if not os.path.exists(args.yara_binary):
        print(f"[ERROR] Error: YARA binary not found at {args.yara_binary}")
        print("SOLUTION: Ensure bin/yara64.exe exists or use --yara-binary to specify path")
        return

    if not os.path.exists(args.yarac_binary):
        print(f"[ERROR] Error: YARA compiler binary not found at {args.yarac_binary}")
        print("SOLUTION: Ensure bin/yarac64.exe exists or use --yarac-binary to specify path")
        return

    print(f"YARA Compiler: {args.yarac_binary}")
    print(f"Target Directory: {args.target_dir}")

    try:
        test_suite = YARATestSuite(args.yara_binary, args.yarac_binary)

        if test_file:
            print(f"Testing syntax of single file: {test_file}")
            if not test_file.exists():
                print(f"[ERROR] Specified YARA file not found: {test_file}")
                return
            test_results = test_suite.test_syntax_only(test_file)
        else:
            target_directory = Path(args.target_dir)
            if not target_directory.exists():
                print(f"[ERROR] Target directory '{args.target_dir}' not found!")
                return
            print(f"Testing syntax of all YARA files in {args.target_dir}")
            test_results = test_suite.test_syntax_all(target_directory)

        # Generate syntax test report
        project_root = Path(args.source_dir).parent
        syntax_report_file = project_root / "yara_syntax_test_report.md"
        test_suite.generate_syntax_report(syntax_report_file)

        print(f"\n[SYNTAX TESTING COMPLETE]!")
        print(f"   Syntax Test Report: {syntax_report_file}")

    except Exception as e:
        print(f"[ERROR] Error during syntax testing: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def handle_functionality_testing(args):
    """Handle functionality testing subcommand"""
    print(f"FUNCTIONALITY TESTING MODE - testing YARA rule functionality only")

    # Determine test target
    test_file = None
    test_all = True

    if hasattr(args, 'file') and args.file:
        test_file = Path(args.file)
        test_all = False
    elif hasattr(args, 'all') and args.all:
        test_all = True

    if not os.path.exists(args.yara_binary):
        print(f"[ERROR] Error: YARA binary not found at {args.yara_binary}")
        print("SOLUTION: Ensure bin/yara64.exe exists or use --yara-binary to specify path")
        return

    print(f"YARA Binary: {args.yara_binary}")
    print(f"Target Directory: {args.target_dir}")

    try:
        test_suite = YARATestSuite(args.yara_binary, args.yarac_binary)

        if test_file:
            print(f"Testing functionality of single file: {test_file}")
            if not test_file.exists():
                print(f"[ERROR] Specified YARA file not found: {test_file}")
                return
            test_results = test_suite.test_functionality_only(test_file)
        else:
            target_directory = Path(args.target_dir)
            if not target_directory.exists():
                print(f"[ERROR] Target directory '{args.target_dir}' not found!")
                return
            print(f"Testing functionality of all YARA files in {args.target_dir}")
            test_results = test_suite.test_functionality_all(target_directory)

        # Generate functionality test report
        project_root = Path(args.source_dir).parent
        functionality_report_file = project_root / "yara_functionality_test_report.md"
        test_suite.generate_functionality_report(functionality_report_file)

        print(f"\n[FUNCTIONALITY TESTING COMPLETE]!")
        print(f"   Functionality Test Report: {functionality_report_file}")

    except Exception as e:
        print(f"[ERROR] Error during functionality testing: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def handle_legacy_testing(args):
    """Handle legacy --test argument for backward compatibility"""
    print(f"[LEGACY MODE] --test argument is deprecated. Use 'test-syntax' or 'test-functionality' subcommands instead.")

    # Map legacy testing to comprehensive testing (both syntax and functionality)
    if not os.path.exists(args.source_dir):
        print(f"[ERROR] Error: Source directory '{args.source_dir}' not found!")
        return

    test_specific_file = None
    if args.test != '__all__':
        test_specific_file = Path(args.test)
    else:
        print(f"Testing all generated YARA files")

    try:
        if not os.path.exists(args.yara_binary):
            print(f"[ERROR] Error: YARA binary not found at {args.yara_binary}")
            return

        if not os.path.exists(args.yarac_binary):
            print(f"[ERROR] Error: YARA compiler binary not found at {args.yarac_binary}")
            return

        test_suite = YARATestSuite(args.yara_binary, args.yarac_binary)

        if test_specific_file:
            test_results = test_suite.test_single_yara_file(test_specific_file)
        else:
            target_directory = Path(args.target_dir)
            if not target_directory.exists():
                print(f"[ERROR] Target directory '{args.target_dir}' not found!")
                return
            test_results = test_suite.test_all_yara_rules(target_directory)

        # Generate comprehensive test report
        project_root = Path(args.source_dir).parent
        test_report_file = project_root / "yara_comprehensive_test_report.md"
        test_suite.generate_test_report(test_report_file)

        print(f"\n[LEGACY TESTING COMPLETE]!")
        print(f"   Recommendation: Use 'test-syntax' or 'test-functionality' for more targeted testing")

    except Exception as e:
        print(f"[ERROR] Error during legacy testing: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def handle_conversion(args):
    """Handle conversion mode"""
    print(f"CONVERSION MODE - converting Python patterns to YARA rules...")

    if not os.path.exists(args.source_dir):
        print(f"[ERROR] Error: Source directory '{args.source_dir}' not found!")
        return

    # Initialize and run converter
    print(f"Starting RE2YARA VERSION_PATTERNS Converter...")
    converter = RE2YARAVersionOnlyConverter(args.source_dir, args.target_dir)
    converter.convert_all(args)
    converter.generate_regex_difference_report()

    print(f"\n[CONVERSION COMPLETE]!")
    print(f"   Generated {len(list(Path(args.target_dir).glob('*.yara')))} YARA rules in {args.target_dir}")
    print(f"   Conversion Report: regex_difference_report.md")
    print(f"   Detailed Trace: regex_difference_trace.json")
    print(f"\n[TO RUN YARA TESTING]:")
    print(f"   python {__file__} test-syntax                                # Test syntax of all YARA rules")
    print(f"   python {__file__} test-functionality                         # Test functionality of all YARA rules")
    print(f"   python {__file__} test-syntax target_yara_version_only/curl_version_only.yara  # Test specific file")
    print(f"   python {__file__} test-functionality target_yara_version_only/curl_version_only.yara  # Test specific file functionality")




if __name__ == "__main__":
    main()