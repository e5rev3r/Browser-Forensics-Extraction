#!/usr/bin/env python3
"""
Firefox Forensics - Report Formatters
=====================================
Multi-format output generators for forensic reports.
Supports HTML, CSV, and Markdown formats with credential highlighting.
"""

import csv
import html
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, List, Dict, Union


# Credential patterns to highlight
CREDENTIAL_KEYWORDS = [
    'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
    'auth', 'session', 'cookie', 'login', 'credential', 'key', 'private',
    'access_token', 'refresh_token', 'bearer', 'oauth', 'jwt'
]

SENSITIVE_FIELDS = [
    'email', 'e-mail', 'mail', 'username', 'user', 'phone', 'mobile',
    'address', 'credit', 'card', 'ssn', 'social', 'bank', 'account'
]


def convert_timestamp(value: Any, field_name: str = "") -> str:
    """Convert Unix timestamps to human-readable format."""
    if value is None or value == '':
        return ''
    
    try:
        # Check if it's a numeric value (timestamp)
        if isinstance(value, (int, float)):
            ts = float(value)
            
            # Detect timestamp format based on magnitude
            if ts > 1e15:  # Microseconds (Firefox places.sqlite)
                ts = ts / 1000000
            elif ts > 1e12:  # Milliseconds
                ts = ts / 1000
            # else: already in seconds
            
            # Sanity check: should be between 2000 and 2100
            if 946684800 < ts < 4102444800:
                return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        
        return str(value)
    except (ValueError, OSError, OverflowError):
        return str(value)


def format_value(value: Any, field_name: str = "") -> str:
    """Format a value for display, converting timestamps and truncating long values."""
    if value is None:
        return ''
    
    # Check if field name suggests a timestamp
    timestamp_fields = ['time', 'date', 'created', 'modified', 'accessed', 'expir', 'last', 'first']
    is_timestamp_field = any(tf in field_name.lower() for tf in timestamp_fields)
    
    if is_timestamp_field and isinstance(value, (int, float)) and value > 1000000000:
        return convert_timestamp(value, field_name)
    
    # Convert to string and truncate if too long
    str_val = str(value)
    if len(str_val) > 100:
        return str_val[:100] + '...'
    
    return str_val


def is_sensitive_field(field_name: str) -> bool:
    """Check if a field name indicates sensitive data."""
    if not field_name:
        return False
    field_lower = str(field_name).lower()
    return any(kw in field_lower for kw in CREDENTIAL_KEYWORDS + SENSITIVE_FIELDS)


def is_credential_value(value: Any) -> bool:
    """Check if a value looks like a credential."""
    if not isinstance(value, str):
        return False
    # Check for common patterns
    if '@' in value and '.' in value:  # Email
        return True
    if value.startswith(('eyJ', 'Bearer ', 'Basic ')):  # JWT/Auth tokens
        return True
    if len(value) > 30 and value.isalnum():  # Long alphanumeric (potential token)
        return True
    return False


@dataclass
class ForensicData:
    """Container for forensic extraction results."""
    profile_path: str
    profile_name: str
    extraction_time: str
    databases: dict  # {db_name: {table_name: [rows]}}
    queries: dict    # {query_name: [rows]}
    json_artifacts: dict  # {file_name: data}
    credentials: list  # Highlighted credentials
    summary: dict  # Extraction summary


class HTMLFormatter:
    """Generate HTML forensic reports with credential highlighting."""
    
    def __init__(self, data: ForensicData):
        self.data = data
    
    def generate(self) -> str:
        """Generate complete HTML report."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firefox Forensics Report - {html.escape(self.data.profile_name)}</title>
    <style>
        {self._get_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header()}
        {self._generate_summary()}
        {self._generate_credentials_section()}
        {self._generate_queries_section()}
        {self._generate_footer()}
    </div>
    <script>
        {self._get_scripts()}
    </script>
</body>
</html>"""
    
    def _get_styles(self) -> str:
        return """
        :root {
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --accent: #e94560;
            --accent-light: #ff6b6b;
            --text: #eaeaea;
            --text-muted: #a0a0a0;
            --success: #00d26a;
            --warning: #ffc107;
            --credential-bg: #ff6b6b22;
            --credential-border: #e94560;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, var(--bg-card), #0f3460);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            border-left: 5px solid var(--accent);
        }
        
        header h1 {
            font-size: 2.5em;
            color: var(--accent);
            margin-bottom: 10px;
        }
        
        header .meta {
            color: var(--text-muted);
            font-size: 0.95em;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        
        .card h2 {
            color: var(--accent);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--accent);
        }
        
        .card h3 {
            color: var(--accent-light);
            margin: 15px 0 10px;
        }
        
        /* Credential Highlighting */
        .credentials-section {
            border: 3px solid var(--accent);
            background: var(--credential-bg);
        }
        
        .credential-item {
            background: rgba(233, 69, 96, 0.15);
            border-left: 4px solid var(--accent);
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        .credential-item .source {
            font-size: 0.85em;
            color: var(--text-muted);
        }
        
        .credential-item .field {
            font-weight: bold;
            color: var(--warning);
        }
        
        .credential-item .value {
            font-family: 'Consolas', monospace;
            background: rgba(0,0,0,0.3);
            padding: 5px 10px;
            border-radius: 3px;
            display: inline-block;
            margin-top: 5px;
            word-break: break-all;
            color: var(--success);
        }
        
        /* Tables */
        .table-wrapper {
            overflow-x: auto;
            margin: 15px 0;
            max-height: 500px;
            overflow-y: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }
        
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        th {
            background: rgba(233, 69, 96, 0.3);
            color: var(--accent-light);
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        tr:nth-child(even) {
            background: rgba(0,0,0,0.2);
        }
        
        tr:hover {
            background: rgba(255,255,255,0.1);
        }
        
        .sensitive-cell {
            background: rgba(233, 69, 96, 0.2) !important;
            color: var(--warning);
            font-weight: bold;
        }
        
        /* Summary Stats */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-item {
            background: rgba(0,0,0,0.2);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: var(--accent);
        }
        
        .stat-label {
            color: var(--text-muted);
            font-size: 0.85em;
            margin-top: 5px;
        }
        
        /* Collapsible Sections */
        .collapsible {
            cursor: pointer;
            user-select: none;
        }
        
        .collapsible::before {
            content: '▶ ';
            display: inline-block;
            transition: transform 0.3s;
        }
        
        .collapsible.active::before {
            transform: rotate(90deg);
        }
        
        .content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        
        .content.show {
            max-height: 100000px;
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            margin: 2px;
        }
        
        .badge-danger { background: var(--accent); }
        .badge-warning { background: var(--warning); color: #000; }
        .badge-success { background: var(--success); color: #000; }
        
        footer {
            text-align: center;
            padding: 20px;
            color: var(--text-muted);
            font-size: 0.85em;
        }
        
        /* Alert Box */
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin: 15px 0;
        }
        
        .alert-danger {
            background: rgba(233, 69, 96, 0.2);
            border: 1px solid var(--accent);
        }
        
        .alert-warning {
            background: rgba(255, 193, 7, 0.2);
            border: 1px solid var(--warning);
        }
        
        .row-count {
            color: var(--text-muted);
            font-size: 0.9em;
            margin-left: 10px;
        }
        """
    
    def _get_scripts(self) -> str:
        return """
        document.querySelectorAll('.collapsible').forEach(item => {
            item.addEventListener('click', function() {
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                content.classList.toggle('show');
            });
        });
        """
    
    def _generate_header(self) -> str:
        return f"""
        <header>
            <h1>🔍 Firefox Forensics Report</h1>
            <div class="meta">
                <p><strong>Profile:</strong> {html.escape(self.data.profile_name)}</p>
                <p><strong>Path:</strong> {html.escape(self.data.profile_path)}</p>
                <p><strong>Extraction Time:</strong> {html.escape(self.data.extraction_time)}</p>
            </div>
        </header>
        """
    
    def _generate_summary(self) -> str:
        summary = self.data.summary
        return f"""
        <div class="card">
            <h2>📊 Extraction Summary</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">{summary.get('databases', 0)}</div>
                    <div class="stat-label">Databases</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{summary.get('tables', 0)}</div>
                    <div class="stat-label">Tables</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{summary.get('total_rows', 0)}</div>
                    <div class="stat-label">Total Records</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{summary.get('json_files', 0)}</div>
                    <div class="stat-label">JSON Files</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{len(self.data.credentials)}</div>
                    <div class="stat-label">Credentials</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_credentials_section(self) -> str:
        if not self.data.credentials:
            return """
            <div class="card credentials-section">
                <h2>🔐 Credentials & Sensitive Data</h2>
                <div class="alert alert-warning">
                    <strong>No credentials found</strong> - No obvious credentials detected in this profile.
                </div>
            </div>
            """
        
        items_html = ""
        for cred in self.data.credentials:
            extra_html = ""
            extra = cred.get('extra', {})
            if extra:
                extra_items = [f"<strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}" 
                              for k, v in extra.items() if v]
                if extra_items:
                    extra_html = f'<div style="margin-top: 8px; font-size: 0.85em; color: var(--text-muted);">{" | ".join(extra_items)}</div>'
            
            items_html += f"""
            <div class="credential-item">
                <div class="source">
                    <span class="badge badge-danger">{html.escape(str(cred.get('source', 'Unknown')))}</span>
                    <span class="badge badge-warning">{html.escape(str(cred.get('type', 'Unknown')))}</span>
                </div>
                <div style="margin-top: 10px;">
                    <span class="field">{html.escape(str(cred.get('field', 'Field')))}:</span>
                    <div class="value">{html.escape(str(cred.get('value', '')))}</div>
                </div>
                {extra_html}
            </div>
            """
        
        return f"""
        <div class="card credentials-section">
            <h2>🔐 Credentials & Sensitive Data</h2>
            <div class="alert alert-danger">
                <strong>⚠️ SENSITIVE DATA FOUND</strong> - {len(self.data.credentials)} credential(s) extracted.
            </div>
            {items_html}
        </div>
        """
    
    def _generate_queries_section(self) -> str:
        if not self.data.queries:
            return ""
        
        sections = ""
        for query_name, rows in self.data.queries.items():
            if not rows:
                continue
            
            table_html = self._generate_table(rows)
            sections += f"""
            <div class="card">
                <h2 class="collapsible">🔎 {html.escape(query_name)} <span class="row-count">({len(rows)} rows)</span></h2>
                <div class="content">
                    {table_html}
                </div>
            </div>
            """
        
        return sections
    
    def _generate_table(self, rows: list) -> str:
        """Generate an HTML table from rows of data."""
        if not rows:
            return "<p>No data</p>"
        
        # Ensure we have dict rows
        if not isinstance(rows[0], dict):
            return "<p>No tabular data available</p>"
        
        columns = list(rows[0].keys())
        
        # Build header
        header_cells = "".join(
            f'<th class="{"sensitive-cell" if is_sensitive_field(col) else ""}">{html.escape(str(col))}</th>'
            for col in columns
        )
        
        # Build rows (limit to first 200 for HTML)
        body_rows = ""
        for row in rows[:200]:
            cells = ""
            for col in columns:
                raw_val = row.get(col, '')
                val = format_value(raw_val, col)
                is_sensitive = is_sensitive_field(col) or is_credential_value(str(raw_val))
                cell_class = 'sensitive-cell' if is_sensitive else ''
                cells += f'<td class="{cell_class}" title="{html.escape(str(raw_val)[:500])}">{html.escape(val)}</td>'
            body_rows += f"<tr>{cells}</tr>"
        
        note = ""
        if len(rows) > 200:
            note = f'<p style="color: var(--warning); margin-top: 10px;">Showing 200 of {len(rows)} rows. See CSV for complete data.</p>'
        
        return f"""
        <div class="table-wrapper">
            <table>
                <thead><tr>{header_cells}</tr></thead>
                <tbody>{body_rows}</tbody>
            </table>
        </div>
        {note}
        """
    
    def _generate_footer(self) -> str:
        return f"""
        <footer>
            <p>Generated by Firefox Forensics Extraction Tool</p>
            <p>{html.escape(self.data.extraction_time)}</p>
        </footer>
        """


class MarkdownFormatter:
    """Generate Markdown forensic reports with credential highlighting."""
    
    def __init__(self, data: ForensicData):
        self.data = data
    
    def generate(self) -> str:
        """Generate complete Markdown report."""
        sections = [
            self._generate_header(),
            self._generate_summary(),
            self._generate_credentials_section(),
            self._generate_queries_section(),
            self._generate_footer()
        ]
        return "\n\n".join(filter(None, sections))
    
    def _generate_header(self) -> str:
        return f"""# 🔍 Firefox Forensics Report

**Profile:** `{self.data.profile_name}`  
**Path:** `{self.data.profile_path}`  
**Extraction Time:** {self.data.extraction_time}

---"""
    
    def _generate_summary(self) -> str:
        s = self.data.summary
        return f"""## 📊 Extraction Summary

| Metric | Value |
|--------|-------|
| Databases | {s.get('databases', 0)} |
| Tables | {s.get('tables', 0)} |
| Total Records | {s.get('total_rows', 0)} |
| JSON Artifacts | {s.get('json_files', 0)} |
| Credentials Found | {len(self.data.credentials)} |"""
    
    def _generate_credentials_section(self) -> str:
        lines = ["## 🔐 Credentials & Sensitive Data", ""]
        
        if not self.data.credentials:
            lines.append("> ⚠️ No obvious credentials detected in this profile.")
            return "\n".join(lines)
        
        lines.append("> ⚠️ **SENSITIVE DATA FOUND** - The following credentials were extracted.")
        lines.append("")
        
        for i, cred in enumerate(self.data.credentials, 1):
            lines.append(f"### Credential #{i}")
            lines.append(f"- **Source:** `{cred.get('source', 'Unknown')}`")
            lines.append(f"- **Type:** `{cred.get('type', 'Unknown')}`")
            lines.append(f"- **Field:** `{cred.get('field', 'Unknown')}`")
            lines.append(f"- **Value:** `{cred.get('value', '')}`")
            
            extra = cred.get('extra', {})
            if extra:
                for k, v in extra.items():
                    if v:
                        lines.append(f"- **{k}:** `{v}`")
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_queries_section(self) -> str:
        if not self.data.queries:
            return ""
        
        lines = ["## 🔎 Forensic Query Results", ""]
        
        for query_name, rows in self.data.queries.items():
            if not rows:
                continue
            
            lines.append(f"### {query_name} ({len(rows)} results)")
            lines.append(self._format_table(rows[:30]))
            
            if len(rows) > 30:
                lines.append(f"*... and {len(rows) - 30} more results (see CSV)*")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_table(self, rows: list) -> str:
        """Format rows as a Markdown table."""
        if not rows:
            return "*No data*"
        
        if not isinstance(rows[0], dict):
            return "*No tabular data*"
        
        columns = list(rows[0].keys())
        
        # Truncate column names for display
        col_display = [str(c)[:15] for c in columns]
        
        lines = []
        lines.append("| " + " | ".join(col_display) + " |")
        lines.append("| " + " | ".join(["---"] * len(columns)) + " |")
        
        for row in rows:
            values = []
            for col in columns:
                raw_val = row.get(col, '')
                val = format_value(raw_val, col)
                # Escape pipe and newline for markdown
                val = val.replace('|', '\\|').replace('\n', ' ')[:40]
                values.append(val)
            lines.append("| " + " | ".join(values) + " |")
        
        return "\n".join(lines)
    
    def _generate_footer(self) -> str:
        return f"""---

*Generated by Firefox Forensics Extraction Tool on {self.data.extraction_time}*"""


class CSVFormatter:
    """Export forensic data to CSV files."""
    
    def __init__(self, data: ForensicData):
        self.data = data
    
    def save_all(self, output_dir: Path) -> list:
        """Save all data to CSV files. Returns list of created files."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        created_files = []
        
        # 1. Save credentials (most important)
        if self.data.credentials:
            cred_file = output_dir / "CREDENTIALS.csv"
            self._save_credentials(cred_file)
            created_files.append(str(cred_file))
        
        # 2. Save forensic query results (key data)
        for query_name, rows in self.data.queries.items():
            if rows and isinstance(rows[0], dict):
                filename = output_dir / f"{query_name}.csv"
                self._save_dict_rows(filename, rows)
                created_files.append(str(filename))
        
        # 3. Save summary
        summary_file = output_dir / "summary.csv"
        self._save_summary(summary_file)
        created_files.append(str(summary_file))
        
        return created_files
    
    def _save_credentials(self, filepath: Path):
        """Save credentials to CSV."""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Source', 'Type', 'Field', 'Value', 'Extra Info'])
            
            for cred in self.data.credentials:
                extra = "; ".join(f"{k}: {v}" for k, v in cred.get('extra', {}).items() if v)
                writer.writerow([
                    cred.get('source', ''),
                    cred.get('type', ''),
                    cred.get('field', ''),
                    cred.get('value', ''),
                    extra
                ])
    
    def _save_dict_rows(self, filepath: Path, rows: list):
        """Save dict rows to CSV with timestamp conversion."""
        if not rows:
            return
        
        columns = list(rows[0].keys())
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            
            for row in rows:
                values = [format_value(row.get(col, ''), col) for col in columns]
                writer.writerow(values)
    
    def _save_summary(self, filepath: Path):
        """Save extraction summary."""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Profile', self.data.profile_name])
            writer.writerow(['Path', self.data.profile_path])
            writer.writerow(['Extraction Time', self.data.extraction_time])
            for k, v in self.data.summary.items():
                writer.writerow([k, v])


class ReportGenerator:
    """Main class to generate reports in all formats."""
    
    def __init__(self, data: ForensicData):
        self.data = data
        self.html_formatter = HTMLFormatter(data)
        self.md_formatter = MarkdownFormatter(data)
        self.csv_formatter = CSVFormatter(data)
    
    def generate_all(self, output_dir: str | Path) -> dict:
        """Generate all report formats."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        results = {
            'html': None,
            'markdown': None,
            'csv_files': []
        }
        
        # HTML Report
        html_path = output_dir / f"report_{self.data.profile_name}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(self.html_formatter.generate())
        results['html'] = str(html_path)
        
        # Markdown Report
        md_path = output_dir / f"report_{self.data.profile_name}.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(self.md_formatter.generate())
        results['markdown'] = str(md_path)
        
        # CSV Files
        results['csv_files'] = self.csv_formatter.save_all(output_dir)
        
        return results


def extract_credentials_from_data(
    databases: dict,
    queries: dict,
    json_artifacts: dict
) -> list:
    """
    Scan all extracted data for credentials and sensitive information.
    Returns list of credential dictionaries.
    """
    credentials = []
    seen_values = set()
    
    def add_credential(source, cred_type, field, value, extra=None):
        """Helper to add credential if not already seen."""
        if not value:
            return
        value_key = f"{source}:{field}:{str(value)[:50]}"
        if value_key not in seen_values:
            seen_values.add(value_key)
            credentials.append({
                'source': source,
                'type': cred_type,
                'field': field,
                'value': str(value),
                'extra': extra or {}
            })
    
    # 1. LOGINS.JSON - Saved passwords/usernames
    if 'logins.json' in json_artifacts:
        logins_data = json_artifacts['logins.json']
        if isinstance(logins_data, dict) and 'logins' in logins_data:
            for login in logins_data['logins']:
                if login.get('username'):
                    add_credential(
                        'logins.json',
                        '🔑 SAVED LOGIN',
                        'Username',
                        login.get('username', ''),
                        {
                            'Website': login.get('hostname', ''),
                            'Times Used': login.get('timesUsed', 0)
                        }
                    )
                if login.get('encryptedPassword'):
                    add_credential(
                        'logins.json',
                        '🔐 ENCRYPTED PASSWORD',
                        'Password',
                        '[ENCRYPTED - Decrypt with Firefox tools]',
                        {'Website': login.get('hostname', '')}
                    )
    
    # 2. AUTH COOKIES
    for query_name in ['auth_high_priority', 'auth_tokens']:
        if query_name in queries:
            for row in queries[query_name]:
                if isinstance(row, dict):
                    add_credential(
                        'cookies.sqlite',
                        '🍪 AUTH COOKIE',
                        row.get('name', ''),
                        str(row.get('value', ''))[:100],
                        {'Host': row.get('host', '')}
                    )
    
    # 3. EMAIL ADDRESSES
    for query_name in ['all_emails', 'email_addresses']:
        if query_name in queries:
            for row in queries[query_name]:
                if isinstance(row, dict):
                    email = row.get('email', row.get('email_address', row.get('value', '')))
                    if email and '@' in str(email):
                        add_credential(
                            'formhistory.sqlite',
                            '📧 EMAIL',
                            'email',
                            email,
                            {'Times Used': row.get('times_used', row.get('timesUsed', 0))}
                        )
    
    # 4. USERNAMES
    if 'usernames' in queries:
        for row in queries['usernames']:
            if isinstance(row, dict):
                add_credential(
                    'formhistory.sqlite',
                    '👤 USERNAME',
                    row.get('fieldname', 'username'),
                    row.get('username', row.get('value', '')),
                    {'Times Used': row.get('times_used', 0)}
                )
    
    # 5. SENSITIVE FORM DATA
    if 'sensitive_fields' in queries:
        for row in queries['sensitive_fields']:
            if isinstance(row, dict):
                field = row.get('fieldname', '')
                if field and is_sensitive_field(field):
                    add_credential(
                        'formhistory.sqlite',
                        '📝 FORM DATA',
                        field,
                        row.get('value', ''),
                        {'Times Used': row.get('timesUsed', 0)}
                    )
    
    # 6. SENSITIVE PERMISSIONS
    for query_name in ['sensitive_permissions', 'granted_permissions']:
        if query_name in queries:
            for row in queries[query_name]:
                if isinstance(row, dict):
                    perm_type = row.get('permission_type', row.get('type', ''))
                    if perm_type in ['geo', 'camera', 'microphone', 'desktop-notification']:
                        add_credential(
                            'permissions.sqlite',
                            '⚠️ PERMISSION',
                            perm_type,
                            row.get('origin', ''),
                            {'Status': row.get('status', 'Granted')}
                        )
    
    # Sort by importance
    priority = {'🔑': 0, '🔐': 1, '🍪': 2, '📧': 3, '👤': 4, '📝': 5, '⚠️': 6}
    credentials.sort(key=lambda x: priority.get(x.get('type', '')[:2], 99))
    
    return credentials


if __name__ == "__main__":
    # Quick test
    test_data = ForensicData(
        profile_path="/test/path",
        profile_name="test.default",
        extraction_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        databases={},
        queries={
            'test_query': [
                {'id': 1, 'url': 'https://example.com', 'visit_time': 1732579200, 'title': 'Test'},
                {'id': 2, 'url': 'https://google.com', 'visit_time': 1732579300, 'title': 'Google'},
            ]
        },
        json_artifacts={},
        credentials=[
            {'source': 'test', 'type': '🔑 SAVED LOGIN', 'field': 'Username', 'value': 'user@test.com', 'extra': {}}
        ],
        summary={'databases': 5, 'tables': 20, 'total_rows': 500, 'json_files': 10}
    )
    
    print("Testing formatters...")
    html = HTMLFormatter(test_data).generate()
    print(f"HTML: {len(html)} bytes")
    
    md = MarkdownFormatter(test_data).generate()
    print(f"Markdown: {len(md)} bytes")
    print("\n--- Sample MD ---")
    print(md[:1000])
