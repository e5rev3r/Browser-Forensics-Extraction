"""SQLite and JSON extraction functions for Firefox forensics."""

import csv
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Dict, Optional, Tuple

from queries import QUERY_REGISTRY


@dataclass
class ExtractionResult:
    """Result of extraction operation."""
    success: bool
    database: str
    rows_extracted: int
    error: Optional[str] = None
    output_path: Optional[Path] = None


class FirefoxDatabaseExtractor:
    """Extract and export data from Firefox SQLite databases."""

    def __init__(self, profile_path: Path):
        """Initialize extractor with Firefox profile path.
        
        Args:
            profile_path: Path to Firefox profile directory.
        """
        self.profile_path = Path(profile_path)
        if not self.profile_path.exists():
            raise FileNotFoundError(f"Profile path not found: {profile_path}")

    def find_databases(self) -> List[Path]:
        """Find all SQLite database files in the profile.
        
        Returns:
            List of Path objects for SQLite files.
        """
        return sorted(self.profile_path.glob("*.sqlite"))

    def find_json_files(self) -> List[Path]:
        """Find all JSON files in the profile.
        
        Returns:
            List of Path objects for JSON files.
        """
        return sorted(self.profile_path.glob("*.json"))

    def get_tables(self, db_path: Path) -> List[str]:
        """Retrieve list of tables in a SQLite database.
        
        Args:
            db_path: Path to SQLite database file.
        
        Returns:
            List of table names.
        """
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            return tables
        except sqlite3.Error as e:
            print(f"Error reading tables from {db_path}: {e}")
            return []

    def export_table_to_csv(
        self, db_path: Path, table_name: str, output_path: Path
    ) -> Tuple[bool, int]:
        """Export a single table to CSV format.
        
        Args:
            db_path: Path to SQLite database.
            table_name: Name of table to export.
            output_path: Path to write CSV file.
        
        Returns:
            Tuple of (success, row_count).
        """
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM \"{table_name}\"")
            rows = cursor.fetchall()
            
            if not rows:
                output_path.write_text("")
                conn.close()
                return True, 0

            # Write CSV with header from columns
            columns = [description[0] for description in cursor.description]
            with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=columns)
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))

            conn.close()
            return True, len(rows)
        except Exception as e:
            print(f"Error exporting table {table_name} from {db_path}: {e}")
            return False, 0

    def run_forensic_query(
        self, db_path: Path, query: str
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Execute a forensic SQL query against a database.
        
        Args:
            db_path: Path to SQLite database.
            query: SQL query string.
        
        Returns:
            Tuple of (result_rows, row_count).
        """
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows], len(rows)
        except sqlite3.Error as e:
            print(f"Error executing query on {db_path}: {e}")
            return [], 0

    def export_query_results_to_csv(
        self,
        db_path: Path,
        query: str,
        output_path: Path,
        query_name: str = "query",
    ) -> Tuple[bool, int]:
        """Export forensic query results to CSV.
        
        Args:
            db_path: Path to SQLite database.
            query: SQL query string.
            output_path: Path to write CSV file.
            query_name: Descriptive name of query.
        
        Returns:
            Tuple of (success, row_count).
        """
        try:
            rows, count = self.run_forensic_query(db_path, query)
            
            if not rows:
                output_path.write_text("")
                return True, 0

            # Write CSV with header from first row keys
            columns = list(rows[0].keys())
            with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=columns)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)

            return True, count
        except Exception as e:
            print(f"Error exporting query results to {output_path}: {e}")
            return False, 0


class FirefoxJSONExtractor:
    """Parse and process Firefox JSON configuration files."""

    @staticmethod
    def parse_extensions(json_path: Path) -> Dict[str, Any]:
        """Parse extensions.json or addons.json file.
        
        Args:
            json_path: Path to JSON file.
        
        Returns:
            Dictionary with addon metadata.
        """
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            addons = data.get("addons", [])
            result = {
                "total_addons": len(addons),
                "addons": [
                    {
                        "id": addon.get("id"),
                        "name": addon.get("name"),
                        "version": addon.get("version"),
                        "type": addon.get("type"),
                        "installDate": addon.get("installDate"),
                        "updateDate": addon.get("updateDate"),
                        "active": addon.get("active"),
                        "permissions": addon.get("permissions", []),
                    }
                    for addon in addons
                ],
            }
            return result
        except Exception as e:
            print(f"Error parsing {json_path}: {e}")
            return {"error": str(e)}

    @staticmethod
    def parse_search_engines(json_path: Path) -> Dict[str, Any]:
        """Parse search.json configuration.
        
        Args:
            json_path: Path to search.json file.
        
        Returns:
            Dictionary with search engine metadata.
        """
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            engines = data.get("engines", [])
            result = {
                "total_engines": len(engines),
                "default_engine": data.get("metaData", {}).get("current", ""),
                "engines": [
                    {
                        "name": engine.get("name"),
                        "url_template": engine.get("urls", [{}])[0].get("template") if engine.get("urls") else "",
                        "alias": engine.get("alias"),
                    }
                    for engine in engines
                ],
            }
            return result
        except Exception as e:
            print(f"Error parsing {json_path}: {e}")
            return {"error": str(e)}

    @staticmethod
    def parse_json_file(json_path: Path) -> Dict[str, Any]:
        """Generic JSON parser for any Firefox JSON file.
        
        Args:
            json_path: Path to JSON file.
        
        Returns:
            Parsed JSON data.
        """
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error parsing {json_path}: {e}")
            return {"error": str(e)}

    @staticmethod
    def save_json_report(data: Dict[str, Any], output_path: Path) -> bool:
        """Save JSON data as readable report.
        
        Args:
            data: Dictionary to save.
            output_path: Path to write JSON file.
        
        Returns:
            Success status.
        """
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving JSON report to {output_path}: {e}")
            return False


class ForensicReportGenerator:
    """Generate summary reports from extracted forensic data."""

    @staticmethod
    def generate_database_summary(
        db_path: Path, tables: List[str], forensic_results: Dict[str, int]
    ) -> str:
        """Generate a text summary for a database.
        
        Args:
            db_path: Path to database file.
            tables: List of tables in database.
            forensic_results: Dictionary mapping query names to row counts.
        
        Returns:
            Formatted summary text.
        """
        summary = f"""# {db_path.name} Summary

## File Information
- **Path**: {db_path}
- **Size**: {db_path.stat().st_size:,} bytes

## Tables ({len(tables)})
"""
        for table in tables:
            summary += f"- {table}\n"

        summary += "\n## Forensic Query Results\n"
        for query_name, row_count in sorted(forensic_results.items()):
            summary += f"- {query_name}: {row_count} rows\n"

        return summary

    @staticmethod
    def generate_master_report(
        profile_path: Path,
        extraction_results: List[ExtractionResult],
        json_summaries: Dict[str, Dict[str, Any]],
        output_dir: Path,
    ) -> str:
        """Generate comprehensive master report.
        
        Args:
            profile_path: Path to Firefox profile.
            extraction_results: List of database extraction results.
            json_summaries: Dictionary of JSON file summaries.
            output_dir: Output directory path.
        
        Returns:
            Formatted master report text.
        """
        report = f"""# Firefox Forensics Extraction Report

## Profile Information
- **Profile Path**: {profile_path}
- **Profile Size**: {sum(p.stat().st_size for p in profile_path.glob('*') if p.is_file()):,} bytes
- **Output Directory**: {output_dir}

## Extraction Summary

### SQLite Databases
"""
        total_rows = 0
        for result in extraction_results:
            status = "✓ Success" if result.success else "✗ Failed"
            report += f"- {result.database}: {status} ({result.rows_extracted} rows)\n"
            total_rows += result.rows_extracted
            if result.error:
                report += f"  Error: {result.error}\n"

        report += f"\n**Total Rows Extracted**: {total_rows:,}\n\n"

        report += "### JSON Files\n"
        for filename, summary in json_summaries.items():
            report += f"- {filename}\n"
            if "error" not in summary:
                for key, value in summary.items():
                    if key != "addons" and key != "engines":
                        report += f"  - {key}: {value}\n"

        report += "\n## Artifact Categories\n"
        report += "- Browsing history and visits\n"
        report += "- Bookmarks and tags\n"
        report += "- Cookies and authentication tokens\n"
        report += "- Form input history and searches\n"
        report += "- Site permissions (geolocation, media, notifications)\n"
        report += "- DOM storage (localStorage, sessionStorage)\n"
        report += "- Favicon metadata\n"
        report += "- Installed extensions and addons\n"
        report += "- Search engine configurations\n"

        report += "\n## Output Files\n"
        report += "All extracted data is organized in the following structure:\n"
        report += "```\n"
        report += "firefox_forensics_output/\n"
        report += "├── databases/           # SQLite database exports (CSV)\n"
        report += "├── forensics/           # Forensic query results (CSV)\n"
        report += "├── reports/             # Database summaries (TXT)\n"
        report += "├── artifacts/           # JSON files (processed)\n"
        report += "└── master_report.md     # This report\n"
        report += "```\n"

        return report
