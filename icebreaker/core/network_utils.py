"""
Network utilities for target expansion and IP handling.
"""
from __future__ import annotations
import ipaddress
from typing import List


def expand_targets(targets: List[str]) -> List[str]:
    """
    Expand target list to handle CIDR notation and IP ranges.

    Args:
        targets: List of targets (IPs, hostnames, or CIDR notation)

    Returns:
        Expanded list of individual targets

    Examples:
        >>> expand_targets(["192.168.1.0/30"])
        ['192.168.1.1', '192.168.1.2']

        >>> expand_targets(["example.com", "192.168.1.1"])
        ['example.com', '192.168.1.1']
    """
    expanded = []

    for target in targets:
        target = target.strip()
        if not target:
            continue

        # Check if it's CIDR notation
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                # Exclude network and broadcast addresses
                hosts = list(network.hosts())
                expanded.extend([str(ip) for ip in hosts])
            except ValueError:
                # Not valid CIDR, add as-is
                expanded.append(target)
        else:
            # Regular IP or hostname
            expanded.append(target)

    return expanded


def is_valid_cidr(target: str) -> bool:
    """
    Check if a string is valid CIDR notation.

    Args:
        target: String to check

    Returns:
        True if valid CIDR notation
    """
    if '/' not in target:
        return False

    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def count_hosts_in_cidr(cidr: str) -> int:
    """
    Count the number of hosts in a CIDR range.

    Args:
        cidr: CIDR notation string

    Returns:
        Number of usable hosts (excluding network/broadcast)
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.num_addresses - 2  # Exclude network and broadcast
    except ValueError:
        return 1  # Not CIDR, count as single host
