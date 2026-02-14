"""
IDOR scanner core: runs the async scan, diffs responses.
"""
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

from .config import ScanConfig
from .models import ScanResult, ScanStats
from .http_client import fetch_url
from .diffing import compare_response

console = Console()
REPORTS_DIR = Path("reports")


async def run_scan_async(
    config: ScanConfig,
) -> Tuple[List[ScanResult], Dict[int, Tuple[Optional[int], int]]]:
    """Run async scan and collect responses."""
    urls = []
    for oid in range(config.id_start, config.id_end + 1):
        url = config.target.replace("{id}", str(oid))
        urls.append((oid, url))

    # init stats
    pattern_stats: Dict[int, Tuple[Optional[int], int]] = {}
    results: List[ScanResult] = []

    if not urls:
        return results, pattern_stats

    # Use proxies via environment (Burp / ZAP)
    async with httpx.AsyncClient(http2=True, timeout=30.0) as client:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"Fuzzing {len(urls)} IDs...", total=len(urls)
            )

            sem = asyncio.Semaphore(config.concurrency)

            async def fetch_with_limit(item: Tuple[int, str]) -> ScanResult:
                async with sem:
                    oid, url = item
                    status, body, error = await fetch_url(client, url, config.headers)

                    body_str = None
                    body_len = 0
                    if body is not None:
                        try:
                            body_str = body.decode("utf-8")
                            body_len = len(body_str)
                        except UnicodeDecodeError:
                            body_len = len(body)

                    # record pattern
                    if body is not None:
                        key = body_len if body_len != 0 else 1
                        pattern_stats[key] = (
                            status,
                            body_len,
                        )

                    return ScanResult(
                        id=oid,
                        url=url,
                        status=status,
                        body=body_str,
                        body_len=body_len,
                        error=error,
                    )

            tasks = [fetch_with_limit(item) for item in urls]
            for coro in asyncio.as_completed(tasks):
                res = await coro
                results.append(res)
                progress.update(task, advance=1)

    return results, pattern_stats


def run_scan(
    config: ScanConfig,
) -> Tuple[List[ScanResult], ScanStats]:
    """
    Synchronous wrapper for the async scan.
    """
    results, patterns = asyncio.run(run_scan_async(config))

    baseline = -1
    if patterns:
        sorted_lens = sorted(patterns.keys(), key=lambda k: patterns[k][1], reverse=True)
        if sorted_lens:
            baseline = sorted_lens[0]

    baseline_status, baseline_len = patterns.get(baseline, (None, 0))

    # calculate stats
    total = 0
    success = 0
    errors = 0
    status_changes = 0
    length_changes = 0

    for r in results:
        total += 1
        if r.status is not None:
            success += 1
        else:
            errors += 1

        # diff against baseline
        if baseline_status is not None:
            r.diff_status = r.status != baseline_status
            if r.diff_status:
                status_changes += 1
        if baseline_len != 0:
            r.diff_len = r.body_len != baseline_len
            if r.diff_len:
                length_changes += 1

    stats
