from __future__ import annotations

from typing import List


def parse_port_spec(spec: str) -> List[int]:
    """
    Parse port specification into list of ports.

    Supports:
    - Single ports: "80"
    - Comma-separated: "80,443,8080"
    - Ranges: "8000-8100"
    - Mixed: "22,80,443,8000-8100"

    Args:
        spec: Port specification string

    Returns:
        List of unique port numbers

    Raises:
        ValueError: If port specification is invalid
    """
    if not spec or not spec.strip():
        raise ValueError("Empty port specification")

    ports = set()

    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue

        if '-' in part:
            # Handle range
            try:
                start_str, end_str = part.split('-', 1)
                start = int(start_str.strip())
                end = int(end_str.strip())

                if start < 1 or end > 65535:
                    raise ValueError(f"Port range {start}-{end} outside valid range (1-65535)")
                if start > end:
                    raise ValueError(f"Invalid port range {start}-{end} (start > end)")

                ports.update(range(start, end + 1))
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid port range: {part}")
                raise
        else:
            # Handle single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port {port} outside valid range (1-65535)")
                ports.add(port)
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid port number: {part}")
                raise

    if not ports:
        raise ValueError("No valid ports in specification")

    return sorted(list(ports))


def get_top_ports(count: int = 100) -> List[int]:
    """
    Get list of most common ports for scanning.

    Args:
        count: Number of top ports to return (100 or 1000)

    Returns:
        List of port numbers
    """
    # Top 100 most common ports
    top_100 = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        20, 69, 123, 137, 138, 161, 389, 631, 1433, 1434,
        3268, 5060, 5061, 8443, 9100, 514, 873, 1900, 3269, 5357,
        49152, 49153, 49154, 8000, 8008, 8081, 8888, 9200, 9300, 5432,
        27017, 6379, 11211, 5672, 15672, 61613, 61614, 1521, 1830, 50000,
        5000, 5001, 8082, 8083, 8084, 8085, 8086, 8087, 8089, 9000,
        9001, 9002, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097,
        9098, 9099, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007,
        10008, 10009, 10010, 3000, 4000, 4443, 7000, 7001, 7002, 7003
    ]

    if count <= 100:
        return top_100[:count]

    # For top 1000, we'd need a more comprehensive list
    # For now, return top 100
    return top_100
