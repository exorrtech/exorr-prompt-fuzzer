"""Report generator — JSON, Markdown, and HTML output."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportGenerator:
    """Generate vulnerability reports from fuzzing results."""

    def __init__(
        self,
        results: List[Dict[str, Any]],
        target: str,
        model: str,
        format: str = "json",
        severity_threshold: str = "low",
    ):
        self.results = results
        self.target = target
        self.model = model
        self.format = format
        self.threshold = SEVERITY_ORDER.get(severity_threshold, 4)

    def _filter_results(self) -> List[Dict[str, Any]]:
        """Filter results by severity threshold."""
        return [
            r for r in self.results
            if SEVERITY_ORDER.get(r.get("severity", "info"), 4) <= self.threshold
        ]

    def _summary(self) -> Dict[str, Any]:
        """Generate scan summary statistics — counts ALL results regardless of filter."""
        vulns = [r for r in self.results if r.get("vulnerable")]
        by_severity = {}
        for v in vulns:
            sev = v.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category = {}
        for v in vulns:
            cat = v.get("category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "target": self.target,
            "model": self.model,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_payloads": len(self.results),
            "vulnerable": len(vulns),
            "safe": len(self.results) - len(vulns),
            "by_severity": by_severity,
            "by_category": by_category,
        }

    def _to_json(self) -> str:
        """Generate JSON report."""
        report = {
            "scanner": "exorr-prompt-fuzzer",
            "version": "1.0.0",
            "summary": self._summary(),
            "results": self._filter_results(),
        }
        return json.dumps(report, indent=2, default=str)

    def _to_markdown(self) -> str:
        """Generate Markdown report."""
        summary = self._summary()
        lines = [
            "# EXORR Prompt Fuzzer Report",
            "",
            f"**Target:** `{summary['target']}`  ",
            f"**Model:** `{summary['model']}`  ",
            f"**Date:** {summary['timestamp']}  ",
            "",
            "## Summary",
            "",
            f"- **Total Payloads:** {summary['total_payloads']}",
            f"- **Vulnerable:** {summary['vulnerable']}",
            f"- **Safe:** {summary['safe']}",
            "",
        ]

        if summary["by_severity"]:
            lines.append("### By Severity")
            lines.append("")
            for sev in ["critical", "high", "medium", "low"]:
                if sev in summary["by_severity"]:
                    lines.append(f"- **{sev.upper()}**: {summary['by_severity'][sev]}")
            lines.append("")

        if summary["by_category"]:
            lines.append("### By Category")
            lines.append("")
            for cat, count in sorted(summary["by_category"].items()):
                lines.append(f"- **{cat}**: {count}")
            lines.append("")

        vulns = [r for r in self._filter_results() if r.get("vulnerable")]
        if vulns:
            lines.append("## Vulnerabilities Found")
            lines.append("")
            for i, v in enumerate(vulns, 1):
                lines.append(f"### {i}. {v.get('payload_name', 'Unknown')}")
                lines.append(f"- **Category:** {v.get('category')}")
                lines.append(f"- **Severity:** {v.get('severity')}")
                lines.append(f"- **Reason:** {v.get('reason')}")
                lines.append(f"- **Prompt:** `{v.get('prompt', '')[:100]}...`")
                if v.get("response_content"):
                    lines.append(f"- **Response:** `{v.get('response_content', '')[:150]}...`")
                lines.append("")

        lines.append("---")
        lines.append("*Walk with the void. EXORR Security*")

        return "\n".join(lines)

    def _to_html(self) -> str:
        """Generate HTML report."""
        summary = self._summary()
        vulns = [r for r in self._filter_results() if r.get("vulnerable")]

        severity_colors = {
            "critical": "#ff0040",
            "high": "#ff4444",
            "medium": "#ffaa00",
            "low": "#44aaff",
            "info": "#888888",
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EXORR Prompt Fuzzer Report</title>
<style>
  :root {{ --green: #00ff41; --bg: #0a0a0a; --text: #c0c0c0; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; background: var(--bg); color: var(--text); padding: 2rem; }}
  h1 {{ color: var(--green); font-size: 1.5rem; margin-bottom: 1rem; }}
  h2 {{ color: var(--green); font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1rem 0; }}
  .stat {{ background: #111; border: 1px solid #222; border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat .num {{ font-size: 2rem; color: var(--green); }}
  .stat .label {{ font-size: 0.8rem; color: #666; }}
  .vuln {{ background: #111; border-left: 3px solid #888; padding: 1rem; margin: 0.5rem 0; border-radius: 0 8px 8px 0; }}
  .severity {{ font-weight: bold; }}
  .critical {{ color: #ff0040; }}
  .high {{ color: #ff4444; }}
  .medium {{ color: #ffaa00; }}
  .low {{ color: #44aaff; }}
  code {{ background: #1a1a1a; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }}
  .footer {{ margin-top: 2rem; color: #333; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>EXORR Prompt Fuzzer Report</h1>
<p>Target: <code>{summary['target']}</code> | Model: <code>{summary['model']}</code> | {summary['timestamp']}</p>

<div class="summary">
  <div class="stat"><div class="num">{summary['total_payloads']}</div><div class="label">Payloads</div></div>
  <div class="stat"><div class="num" style="color:#ff0040">{summary['vulnerable']}</div><div class="label">Vulnerable</div></div>
  <div class="stat"><div class="num" style="color:#00ff41">{summary['safe']}</div><div class="label">Safe</div></div>
</div>
"""

        if vulns:
            html += "<h2>Vulnerabilities</h2>\n"
            for v in vulns:
                sev = v.get("severity", "info")
                html += f"""<div class="vuln" style="border-left-color:{severity_colors.get(sev, '#888')}">
  <span class="severity {sev}">[{sev.upper()}]</span> <strong>{v.get('payload_name')}</strong> ({v.get('category')})<br>
  <small>{v.get('reason')}</small><br>
  <code>{v.get('prompt', '')[:120]}...</code>
</div>\n"""

        html += '<div class="footer">Walk with the void. EXORR Security</div></body></html>'
        return html

    def save(self, path: str) -> None:
        """Save report to file."""
        if self.format == "json":
            content = self._to_json()
        elif self.format == "markdown":
            content = self._to_markdown()
        elif self.format == "html":
            content = self._to_html()
        else:
            content = self._to_json()

        Path(path).write_text(content, encoding="utf-8")
