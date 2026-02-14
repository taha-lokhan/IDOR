"""
Report generation in JSON, TXT, and HTML formats.
"""
import json
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from jinja2 import Template

from .models import ScanResult, ScanStats
from .diffing import get_anomalies, group_by_pattern

REPORTS_DIR = Path("reports")


def ensure_reports_dir() -> Path:
    """Create reports directory if it doesn't exist."""
    REPORTS_DIR.mkdir(exist_ok=True)
    return REPORTS_DIR


def generate_timestamp() -> str:
    """Generate timestamp for report filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def generate_json_report(
    results: List[ScanResult],
    stats: ScanStats,
    target: str,
    output_path: Path,
) -> None:
    """Generate JSON report with structured data."""
    report_data = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "total_scanned": stats.total,
        },
        "statistics": stats.as_dict(),
        "results": [
            {
                "id": r.id,
                "url": r.url,
                "status": r.status,
                "body_length": r.body_len,
                "error": r.error,
                "diff_status": r.diff_status,
                "diff_length": r.diff_len,
            }
            for r in results
        ],
        "anomalies": [
            {
                "id": r.id,
                "url": r.url,
                "status": r.status,
                "body_length": r.body_len,
                "reason": (
                    "Status code differs" if r.diff_status else ""
                ) + (
                    " | " if (r.diff_status and r.diff_len) else ""
                ) + (
                    "Body length differs" if r.diff_len else ""
                ),
            }
            for r in get_anomalies(results)
        ],
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)


def generate_txt_report(
    results: List[ScanResult],
    stats: ScanStats,
    target: str,
    output_path: Path,
) -> None:
    """Generate human-readable TXT report."""
    anomalies = get_anomalies(results)
    
    lines = []
    lines.append("=" * 70)
    lines.append("IDOR SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Target: {target}")
    lines.append("")
    
    lines.append("STATISTICS")
    lines.append("-" * 70)
    lines.append(f"Total scanned:      {stats.total}")
    lines.append(f"Successful:         {stats.success}")
    lines.append(f"Errors:             {stats.errors}")
    lines.append(f"Status changes:     {stats.status_changes}")
    lines.append(f"Length changes:     {stats.length_changes}")
    lines.append("")
    
    if anomalies:
        lines.append("ANOMALIES DETECTED (Potential IDOR vulnerabilities)")
        lines.append("-" * 70)
        for anomaly in anomalies:
            lines.append(f"ID: {anomaly.id}")
            lines.append(f"  URL: {anomaly.url}")
            lines.append(f"  Status: {anomaly.status}")
            lines.append(f"  Body Length: {anomaly.body_len}")
            reasons = []
            if anomaly.diff_status:
                reasons.append("Status differs from baseline")
            if anomaly.diff_len:
                reasons.append("Length differs from baseline")
            lines.append(f"  Reason: {', '.join(reasons)}")
            lines.append("")
    else:
        lines.append("NO ANOMALIES DETECTED")
        lines.append("-" * 70)
        lines.append("All responses match the baseline pattern.")
        lines.append("")
    
    lines.append("RESPONSE PATTERNS")
    lines.append("-" * 70)
    patterns = group_by_pattern(results)
    for (status, length), items in sorted(
        patterns.items(), key=lambda x: len(x[1]), reverse=True
    ):
        lines.append(f"Status {status}, Length {length}: {len(items)} occurrences")
        lines.append(f"  IDs: {', '.join(str(r.id) for r in items[:10])}")
        if len(items) > 10:
            lines.append(f"  ... and {len(items) - 10} more")
        lines.append("")
    
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def generate_html_report(
    results: List[ScanResult],
    stats: ScanStats,
    target: str,
    output_path: Path,
) -> None:
    """Generate interactive HTML dashboard."""
    anomalies = get_anomalies(results)
    patterns = group_by_pattern(results)
    
    # HTML template
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDOR Scan Report - {{ timestamp }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        .stat-card h3 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .stat-card p {
            font-size: 1em;
            opacity: 0.9;
        }
        .alert {
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .alert.danger {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        .alert.success {
            background: #d4edda;
            border-left-color: #28a745;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        thead {
            background: #667eea;
            color: white;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        tbody tr:hover {
            background: #f8f9ff;
        }
        .status-200 { color: #28a745; font-weight: bold; }
        .status-403 { color: #ffc107; font-weight: bold; }
        .status-404 { color: #6c757d; font-weight: bold; }
        .status-500 { color: #dc3545; font-weight: bold; }
        .diff-yes { 
            background: #ffc107; 
            color: white; 
            padding: 3px 8px; 
            border-radius: 3px;
            font-weight: bold;
        }
        .diff-no { 
            color: #28a745;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }
        .pattern-box {
            background: #f8f9ff;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IDOR Scan Report</h1>
            <p>{{ timestamp }}</p>
            <p><strong>Target:</strong> {{ target }}</p>
        </div>
        
        <div class="content">
            <!-- Statistics Section -->
            <div class="section">
                <h2>Scan Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>{{ stats.total }}</h3>
                        <p>Total Scanned</p>
                    </div>
                    <div class="stat-card">
                        <h3>{{ stats.success }}</h3>
                        <p>Successful</p>
                    </div>
                    <div class="stat-card">
                        <h3>{{ stats.errors }}</h3>
                        <p>Errors</p>
                    </div>
                    <div class="stat-card">
                        <h3>{{ stats.status_changes }}</h3>
                        <p>Status Changes</p>
                    </div>
                    <div class="stat-card">
                        <h3>{{ stats.length_changes }}</h3>
                        <p>Length Changes</p>
                    </div>
                </div>
            </div>
            
            <!-- Anomalies Section -->
            <div class="section">
                <h2>Anomalies Detected</h2>
                {% if anomalies %}
                <div class="alert danger">
                    <strong>Warning:</strong> {{ anomalies|length }} potential IDOR vulnerabilities detected!
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Status</th>
                            <th>Body Length</th>
                            <th>Diff Status</th>
                            <th>Diff Length</th>
                            <th>URL</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for anomaly in anomalies %}
                        <tr>
                            <td>{{ anomaly.id }}</td>
                            <td class="status-{{ anomaly.status }}">{{ anomaly.status }}</td>
                            <td>{{ anomaly.body_len }}</td>
                            <td>
                                {% if anomaly.diff_status %}
                                <span class="diff-yes">YES</span>
                                {% else %}
                                <span class="diff-no">NO</span>
                                {% endif %}
                            </td>
                            <td>
                                {% if anomaly.diff_len %}
                                <span class="diff-yes">YES</span>
                                {% else %}
                                <span class="diff-no">NO</span>
                                {% endif %}
                            </td>
                            <td><code>{{ anomaly.url }}</code></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="alert success">
                    <strong>Good news:</strong> No anomalies detected. All responses match the baseline pattern.
                </div>
                {% endif %}
            </div>
            
            <!-- Response Patterns Section -->
            <div class="section">
                <h2>Response Patterns</h2>
                {% for pattern in patterns %}
                <div class="pattern-box">
                    <strong>Status {{ pattern.status }}, Length {{ pattern.length }}</strong>
                    <br>
                    Occurrences: {{ pattern.count }}
                    <br>
                    IDs: {{ pattern.ids }}
                </div>
                {% endfor %}
            </div>
            
            <!-- All Results Section -->
            <div class="section">
                <h2>All Scan Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Status</th>
                            <th>Body Length</th>
                            <th>Diff</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for result in results %}
                        <tr>
                            <td>{{ result.id }}</td>
                            <td class="status-{{ result.status }}">{{ result.status or 'ERROR' }}</td>
                            <td>{{ result.body_len }}</td>
                            <td>
                                {% if result.diff_status or result.diff_len %}
                                <span class="diff-yes">Y</span>
                                {% else %}
                                <span class="diff-no">N</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by IDOR Scanner | Insecure Direct Object Reference Detection Tool</p>
            <p><strong>Legal Notice:</strong> This tool is for authorized security testing only.</p>
        </div>
    </div>
</body>
</html>
    """
    
    # Prepare pattern data for template
    pattern_data = []
    for (status, length), items in sorted(
        patterns.items(), key=lambda x: len(x[1]), reverse=True
    ):
        ids_str = ", ".join(str(r.id) for r in items[:15])
        if len(items) > 15:
            ids_str += f" ... and {len(items) - 15} more"
        
        pattern_data.append({
            "status": status,
            "length": length,
            "count": len(items),
            "ids": ids_str,
        })
    
    # Render template
    template = Template(html_template)
    html_content = template.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        stats=stats,
        anomalies=anomalies,
        patterns=pattern_data,
        results=results,
    )
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_reports(
    results: List[ScanResult],
    stats: ScanStats,
    target: str,
) -> None:
    """Generate all report formats (JSON, TXT, HTML)."""
    ensure_reports_dir()
    timestamp = generate_timestamp()
    
    base_name = f"scan_{timestamp}"
    
    json_path = REPORTS_DIR / f"{base_name}.json"
    txt_path = REPORTS_DIR / f"{base_name}.txt"
    html_path = REPORTS_DIR / f"{base_name}.html"
    
    generate_json_report(results, stats, target, json_path)
    generate_txt_report(results, stats, target, txt_path)
    generate_html_report(results, stats, target, html_path)
    
    print(f"\n✓ Reports generated:")
    print(f"  • JSON: {json_path}")
    print(f"  • TXT:  {txt_path}")
    print(f"  • HTML: {html_path}")


def open_report_dashboard() -> None:
    """Open the latest HTML report in the default web browser."""
    if not REPORTS_DIR.exists():
        print("No reports directory found. Run a scan first.")
        return
    
    html_files = sorted(REPORTS_DIR.glob("scan_*.html"), reverse=True)
    
    if not html_files:
        print("No HTML reports found. Run a scan first.")
        return
    
    latest_report = html_files[0]
    print(f"Opening dashboard: {latest_report}")
    
    webbrowser.open(f"file://{latest_report.resolve()}")
