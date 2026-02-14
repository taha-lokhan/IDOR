"""
Configuration handling (YAML + ScanConfig).
"""
from dataclasses import dataclass
from typing import Dict, Optional
import yaml


@dataclass
class ScanConfig:
    """Configuration for a single IDOR scan."""
    target: str
    id_start: int
    id_end: int
    headers: Optional[Dict[str, str]] = None
    concurrency: int = 5


def load_config(path: str) -> ScanConfig:
    """
    Load a YAML configuration file into a ScanConfig.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    target = data.get("target")
    if not target:
        raise ValueError("YAML config must have 'target' field")

    ids = data.get("id_range", [1, 10])
    if len(ids) != 2:
        raise ValueError("id_range must be a list of two integers")

    headers_data = data.get("headers", [])
    if isinstance(headers_data, (str, list)):
        if isinstance(headers_data, str):
            headers_data = [headers_data]
    else:
        headers_data = []

    headers = {}
    for h in headers_data:
        if ":" not in h:
            raise ValueError(
                f"Header must be in KEY:VALUE format: {h}"
            )
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()

    concurrency = data.get("concurrency", 5)

    return ScanConfig(
        target=target,
        id_start=ids[0],
        id_end=ids[1],
        headers=headers,
        concurrency=concurrency,
    )

