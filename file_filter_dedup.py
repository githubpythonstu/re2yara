#!/usr/bin/env python3
"""
File Filter and Deduplication Script
Moves checker files from checkers/ to source_python_re/
excluding files that match existing YARA rule names in signatures/
"""

import os
import re
import shutil
from pathlib import Path
from typing import Set, Dict, List
import logging

class FileFilterDeduplicator:
    """Filters and deduplicates checker files based on YARA rule names"""

    def __init__(self, signatures_dir: str = "signatures",
                 checkers_dir: str = "checkers",
                 target_dir: str = "source_python_re"):
        self.signatures_dir = Path(signatures_dir)
        self.checkers_dir = Path(checkers_dir)
        self.target_dir = Path(target_dir)

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Statistics
        self.stats = {
            'total_yara_rules': 0,
            'total_checker_files': 0,
            'filtered_files': 0,
            'copied_files': 0,
            'skipped_files': 0
        }

    def parse_yara_rules(self) -> Set[str]:
        """Parse all YARA files and extract rule names"""
        rule_names = set()

        if not self.signatures_dir.exists():
            self.logger.warning(f"Signatures directory {self.signatures_dir} does not exist")
            return rule_names

        self.logger.info("Parsing YARA rules from signatures directory...")

        for yara_file in self.signatures_dir.glob("*.yara"):
            try:
                with open(yara_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Extract rule names using regex
                # Pattern matches: rule RULE_NAME { or rule\tRULE_NAME{ etc.
                rule_matches = re.findall(r'^\s*rule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{', content, re.MULTILINE)

                for rule_name in rule_matches:
                    rule_names.add(rule_name)

                self.logger.debug(f"Found {len(rule_matches)} rules in {yara_file.name}")

            except Exception as e:
                self.logger.error(f"Error parsing {yara_file}: {e}")

        self.stats['total_yara_rules'] = len(rule_names)
        self.logger.info(f"Found {len(rule_names)} total YARA rule names")

        return rule_names

    def get_checker_files(self) -> List[Path]:
        """Get all Python checker files"""
        checker_files = []

        if not self.checkers_dir.exists():
            self.logger.error(f"Checkers directory {self.checkers_dir} does not exist")
            return checker_files

        # Get all .py files except __init__.py
        for py_file in self.checkers_dir.glob("*.py"):
            if py_file.name != "__init__.py":
                checker_files.append(py_file)

        self.stats['total_checker_files'] = len(checker_files)
        self.logger.info(f"Found {len(checker_files)} checker files")

        return checker_files

    def should_copy_file(self, checker_file: Path, rule_names: Set[str]) -> bool:
        """Determine if a checker file should be copied based on rule name matching"""

        # Get the base filename without extension
        base_name = checker_file.stem

        # Direct rule name match
        if base_name in rule_names:
            return False

        # Case-insensitive match
        for rule_name in rule_names:
            if base_name.lower() == rule_name.lower():
                return False

        # Handle common naming variations
        variations = [
            base_name.replace('_', ''),      # remove underscores
            base_name.replace('-', ''),      # remove hyphens
            base_name.lower(),               # lowercase
            base_name.upper(),               # uppercase
            base_name.capitalize(),          # capitalize first letter
        ]

        for variation in variations:
            if variation in rule_names:
                return False

        # Check for partial matches (e.g., "apache_http_server" vs "Apache")
        for rule_name in rule_names:
            rule_lower = rule_name.lower()
            base_lower = base_name.lower()

            # If base name contains rule name or vice versa
            if rule_lower in base_lower or base_lower in rule_lower:
                # Additional check to avoid false positives
                if self.is_likely_match(base_lower, rule_lower):
                    return False

        return True

    def is_likely_match(self, base_name: str, rule_name: str) -> bool:
        """Heuristic to determine if base name and rule name likely refer to the same software"""

        # Normalize both names
        base_normalized = re.sub(r'[_\-]', '', base_name.lower())
        rule_normalized = re.sub(r'[_\-]', '', rule_name.lower())

        # Exact match after normalization
        if base_normalized == rule_normalized:
            return True

        # Check if one is a prefix of the other (with reasonable length)
        if len(rule_normalized) >= 3:
            if base_normalized.startswith(rule_normalized) or rule_normalized.startswith(base_normalized):
                return True

        # Check for common software name patterns
        # Extract the first meaningful word
        base_words = re.findall(r'[a-z]{2,}', base_normalized)
        rule_words = re.findall(r'[a-z]{2,}', rule_normalized)

        if base_words and rule_words:
            # If first 3+ letters match
            if base_words[0][:3] == rule_words[0][:3]:
                return True

        return False

    def copy_filtered_files(self, checker_files: List[Path], rule_names: Set[str]) -> Dict[str, List[str]]:
        """Copy checker files that don't match existing rule names"""

        # Ensure target directory exists
        self.target_dir.mkdir(exist_ok=True)

        copied_files = []
        skipped_files = []

        self.logger.info("Starting file filtering and copying...")

        for checker_file in checker_files:
            try:
                if self.should_copy_file(checker_file, rule_names):
                    # Copy the file
                    target_path = self.target_dir / checker_file.name
                    shutil.copy2(checker_file, target_path)
                    copied_files.append(checker_file.name)
                    self.logger.debug(f"Copied: {checker_file.name}")
                else:
                    skipped_files.append(checker_file.name)
                    self.logger.debug(f"Skipped (matches existing rule): {checker_file.name}")

            except Exception as e:
                self.logger.error(f"Error processing {checker_file}: {e}")
                skipped_files.append(f"{checker_file.name} (error: {e})")

        self.stats['copied_files'] = len([f for f in copied_files if not f.startswith('(')])
        self.stats['skipped_files'] = len(skipped_files)

        return {
            'copied': copied_files,
            'skipped': skipped_files
        }

    def generate_report(self, results: Dict[str, List[str]]) -> str:
        """Generate a detailed report of the filtering process"""

        report_lines = [
            "# File Filtering and Deduplication Report\n",
            f"Generated on: {os.popen('date').read().strip()}",
            "",
            "## Summary Statistics",
            f"- Total YARA rules found: {self.stats['total_yara_rules']}",
            f"- Total checker files: {self.stats['total_checker_files']}",
            f"- Files copied to source_python_re/: {self.stats['copied_files']}",
            f"- Files skipped (existing rules): {self.stats['skipped_files']}",
            "",
            "## Copied Files (New Checkers)",
            ""
        ]

        if results['copied']:
            for filename in results['copied']:
                if not filename.startswith('('):  # Skip error entries
                    report_lines.append(f"- `{filename}`")
        else:
            report_lines.append("No files were copied.")

        report_lines.extend([
            "",
            "## Skipped Files (Matching Existing Rules)",
            ""
        ])

        if results['skipped']:
            for filename in results['skipped']:
                report_lines.append(f"- `{filename}`")
        else:
            report_lines.append("No files were skipped.")

        report_lines.extend([
            "",
            "## Filtering Logic",
            "Files were skipped if they:",
            "1. Directly match an existing YARA rule name",
            "2. Match case-insensitively",
            "3. Match after removing underscores/hyphens",
            "4. Are likely variations of the same software name",
            "",
            "## Next Steps",
            "The copied files in `source_python_re/` can now be used with:",
            "- `py re2yara_converter.py` (full conversion)",
            "- `py re2yara_version_only_converter.py` (version-only conversion)",
            ""
        ])

        return "\n".join(report_lines)

    def run(self) -> Dict[str, List[str]]:
        """Execute the complete filtering and deduplication process"""

        self.logger.info("Starting file filtering and deduplication...")

        # Step 1: Parse existing YARA rules
        rule_names = self.parse_yara_rules()

        # Step 2: Get all checker files
        checker_files = self.get_checker_files()

        if not checker_files:
            self.logger.error("No checker files found to process")
            return {'copied': [], 'skipped': []}

        # Step 3: Filter and copy files
        results = self.copy_filtered_files(checker_files, rule_names)

        # Step 4: Generate and save report
        report = self.generate_report(results)

        report_file = Path("file_filtering_report.md")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)

        self.logger.info(f"Process completed. Report saved to {report_file}")
        self.logger.info(f"Copied {self.stats['copied_files']} files, skipped {self.stats['skipped_files']} files")

        # Print summary to console
        print("\n" + "="*60)
        print("FILE FILTERING SUMMARY")
        print("="*60)
        print(f"YARA rules parsed: {self.stats['total_yara_rules']}")
        print(f"Checker files processed: {self.stats['total_checker_files']}")
        print(f"Files copied: {self.stats['copied_files']}")
        print(f"Files skipped: {self.stats['skipped_files']}")
        print(f"Report saved to: {report_file}")
        print("="*60)

        return results


def main():
    """Main entry point"""
    import sys

    print("File Filter and Deduplication Script")
    print("=====================================")
    print("This script filters checker files from checkers/ directory")
    print("and copies only non-duplicate files to source_python_re/")
    print("based on existing YARA rule names in signatures/ directory")
    print()

    # Create and run the filter
    filter_tool = FileFilterDeduplicator()

    try:
        results = filter_tool.run()

        if results['copied']:
            print(f"\n[SUCCESS] Successfully copied {len(results['copied'])} new files to source_python_re/")
        else:
            print("\n[INFO] No new files to copy - all checker files match existing rules")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()