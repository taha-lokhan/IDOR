"""
Response comparison and baseline detection for IDOR analysis.
"""
from typing import Dict, List, Optional, Tuple
from collections import Counter

from .models import ScanResult


def find_baseline_pattern(
    results: List[ScanResult],
) -> Tuple[Optional[int], int]:
    """
    Find the most common response pattern (status + body_len).
    Returns (baseline_status, baseline_length).
    
    The baseline represents "normal" responses that are likely legitimate.
    Deviations from this baseline may indicate IDOR vulnerabilities.
    """
    if not results:
        return None, 0
    
    # Count status code + body length combinations
    patterns: Dict[Tuple[Optional[int], int], int] = {}
    
    for result in results:
        if result.status is not None:
            key = (result.status, result.body_len)
            patterns[key] = patterns.get(key, 0) + 1
    
    if not patterns:
        return None, 0
    
    # Find most common pattern
    most_common = max(patterns.items(), key=lambda x: x[1])
    baseline_status, baseline_len = most_common[0]
    
    return baseline_status, baseline_len


def find_baseline_by_status(
    results: List[ScanResult],
) -> Optional[int]:
    """
    Find the most common HTTP status code across all results.
    """
    if not results:
        return None
    
    status_codes = [r.status for r in results if r.status is not None]
    
    if not status_codes:
        return None
    
    counter = Counter(status_codes)
    most_common_status = counter.most_common(1)[0][0]
    
    return most_common_status


def find_baseline_by_length(
    results: List[ScanResult],
) -> int:
    """
    Find the most common response body length across all results.
    """
    if not results:
        return 0
    
    lengths = [r.body_len for r in results if r.status is not None]
    
    if not lengths:
        return 0
    
    counter = Counter(lengths)
    most_common_length = counter.most_common(1)[0][0]
    
    return most_common_length


def compare_response(
    result: ScanResult,
    baseline_status: Optional[int],
    baseline_length: int,
) -> Tuple[bool, bool]:
    """
    Compare a single result against baseline values.
    
    Returns:
        (diff_status, diff_len) - True if different from baseline
    """
    diff_status = False
    diff_len = False
    
    if baseline_status is not None and result.status is not None:
        diff_status = result.status != baseline_status
    
    if baseline_length > 0 and result.body_len > 0:
        diff_len = result.body_len != baseline_length
    
    return diff_status, diff_len


def mark_anomalies(
    results: List[ScanResult],
) -> List[ScanResult]:
    """
    Mark all results that differ from the baseline pattern.
    Updates the diff_status and diff_len fields in each ScanResult.
    
    Returns the same list with updated diff flags.
    """
    baseline_status, baseline_length = find_baseline_pattern(results)
    
    for result in results:
        if result.status is not None:
            result.diff_status = (
                result.status != baseline_status 
                if baseline_status is not None 
                else None
            )
            result.diff_len = (
                result.body_len != baseline_length 
                if baseline_length > 0 
                else None
            )
    
    return results


def get_anomalies(
    results: List[ScanResult],
) -> List[ScanResult]:
    """
    Filter and return only the anomalous results (potential IDOR vulnerabilities).
    
    An anomaly is any result that differs in status code OR body length
    from the baseline pattern.
    """
    anomalies = []
    
    for result in results:
        if result.diff_status or result.diff_len:
            anomalies.append(result)
    
    return anomalies


def calculate_similarity_score(
    result1: ScanResult,
    result2: ScanResult,
) -> float:
    """
    Calculate similarity score between two results (0.0 to 1.0).
    
    Used for advanced clustering of response patterns.
    """
    if result1.status is None or result2.status is None:
        return 0.0
    
    score = 0.0
    
    # Status code match (50% weight)
    if result1.status == result2.status:
        score += 0.5
    
    # Body length similarity (50% weight)
    if result1.body_len > 0 and result2.body_len > 0:
        len_diff = abs(result1.body_len - result2.body_len)
        max_len = max(result1.body_len, result2.body_len)
        len_similarity = 1.0 - (len_diff / max_len)
        score += 0.5 * len_similarity
    elif result1.body_len == result2.body_len:
        score += 0.5
    
    return score


def group_by_pattern(
    results: List[ScanResult],
) -> Dict[Tuple[Optional[int], int], List[ScanResult]]:
    """
    Group results by their response pattern (status + body_len).
    
    Useful for identifying multiple response patterns that may indicate
    different authorization levels or data access patterns.
    """
    groups: Dict[Tuple[Optional[int], int], List[ScanResult]] = {}
    
    for result in results:
        key = (result.status, result.body_len)
        if key not in groups:
            groups[key] = []
        groups[key].append(result)
    
    return groups
