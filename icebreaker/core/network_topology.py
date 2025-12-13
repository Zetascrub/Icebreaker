"""
Network topology analyzer for building network maps from scan results.
"""
from __future__ import annotations
from typing import Dict, List, Any, Set
from collections import defaultdict
import ipaddress
from sqlalchemy.orm import Session

from icebreaker.db.models import Scan, Service, Finding


class NetworkTopology:
    """Analyzes scan results to build network topology."""

    def __init__(self, db: Session):
        self.db = db

    def build_topology(self, scan_ids: List[int] = None, limit: int = None) -> Dict[str, Any]:
        """
        Build network topology from scan results.

        Args:
            scan_ids: List of scan IDs to include (None = all scans)
            limit: Limit number of nodes (for performance)

        Returns:
            Dictionary with nodes and edges for network graph
        """
        # Get scans to analyze
        query = self.db.query(Scan)
        if scan_ids:
            query = query.filter(Scan.id.in_(scan_ids))
        scans = query.all()

        # Build network graph
        nodes = {}  # host -> node data
        edges = []  # connections between hosts
        host_services = defaultdict(list)  # host -> services
        host_findings = defaultdict(list)  # host -> findings

        # Collect all hosts and their services
        for scan in scans:
            services = self.db.query(Service).filter(Service.scan_id == scan.id).all()

            for service in services:
                host = service.target

                # Add service to host
                host_services[host].append({
                    'port': service.port,
                    'name': service.name,
                    'meta': service.meta
                })

                # Initialize node if not exists
                if host not in nodes:
                    nodes[host] = {
                        'id': host,
                        'label': host,
                        'type': self._classify_host(host),
                        'services': [],
                        'findings': [],
                        'risk_score': 0,
                        'open_ports': 0
                    }

        # Collect findings for each host
        for scan in scans:
            findings = self.db.query(Finding).filter(
                Finding.scan_id == scan.id,
                Finding.false_positive == False
            ).all()

            for finding in findings:
                host = finding.target
                if host in nodes:
                    host_findings[host].append({
                        'severity': finding.severity,
                        'title': finding.title,
                        'port': finding.port,
                        'risk_score': finding.risk_score or 0
                    })

        # Aggregate data into nodes
        for host, node in nodes.items():
            # Add services
            node['services'] = host_services[host]
            node['open_ports'] = len(host_services[host])

            # Add findings
            node['findings'] = host_findings[host]

            # Calculate risk score
            severity_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2, 'INFO': 1}
            total_risk = sum(
                severity_weights.get(f['severity'], 0)
                for f in host_findings[host]
            )
            node['risk_score'] = total_risk

            # Determine node color based on risk
            node['color'] = self._get_risk_color(total_risk)
            node['size'] = min(10 + node['open_ports'] * 2, 50)  # Size based on services

        # Build edges (connections between hosts on same network)
        edges = self._build_edges(list(nodes.keys()))

        # Apply limit if specified
        if limit and len(nodes) > limit:
            # Sort by risk score and take top N
            sorted_hosts = sorted(
                nodes.keys(),
                key=lambda h: nodes[h]['risk_score'],
                reverse=True
            )[:limit]
            nodes = {h: nodes[h] for h in sorted_hosts}
            # Rebuild edges for limited nodes
            edges = self._build_edges(sorted_hosts)

        # Convert nodes dict to list
        nodes_list = list(nodes.values())

        return {
            'nodes': nodes_list,
            'edges': edges,
            'stats': {
                'total_hosts': len(nodes_list),
                'total_services': sum(n['open_ports'] for n in nodes_list),
                'total_findings': sum(len(n['findings']) for n in nodes_list),
                'high_risk_hosts': len([n for n in nodes_list if n['risk_score'] >= 20])
            }
        }

    def _classify_host(self, host: str) -> str:
        """Classify host type based on IP address."""
        try:
            ip = ipaddress.ip_address(host)

            # Check for special addresses
            if ip.is_private:
                return 'internal'
            elif ip.is_loopback:
                return 'localhost'
            elif ip.is_multicast:
                return 'multicast'
            else:
                return 'external'
        except ValueError:
            # It's a hostname, not an IP
            return 'hostname'

    def _get_risk_color(self, risk_score: int) -> str:
        """Get color based on risk score."""
        if risk_score >= 30:
            return '#dc2626'  # red - critical
        elif risk_score >= 15:
            return '#ea580c'  # orange - high
        elif risk_score >= 5:
            return '#d97706'  # amber - medium
        elif risk_score > 0:
            return '#65a30d'  # lime - low
        else:
            return '#0284c7'  # blue - no findings

    def _build_edges(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """
        Build edges (connections) between hosts on same network.

        Args:
            hosts: List of host addresses

        Returns:
            List of edge dictionaries
        """
        edges = []
        networks = defaultdict(list)

        # Group hosts by network
        for host in hosts:
            try:
                ip = ipaddress.ip_address(host)
                # Group by /24 network
                if ip.version == 4:
                    network = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                else:
                    network = str(ipaddress.IPv6Network(f"{ip}/64", strict=False))

                networks[network].append(host)
            except ValueError:
                # Hostname - put in special group
                networks['hostnames'].append(host)

        # Create edges within each network (star topology from first host)
        for network, network_hosts in networks.items():
            if len(network_hosts) > 1:
                # Connect all hosts to the first host (hub)
                hub = network_hosts[0]
                for host in network_hosts[1:]:
                    edges.append({
                        'from': hub,
                        'to': host,
                        'label': network if network != 'hostnames' else 'network',
                        'dashes': network == 'hostnames'  # Dashed line for hostnames
                    })

        return edges
