"""
Network topology analyzer for building network maps from scan results.
"""
from __future__ import annotations
from typing import Dict, List, Any, Set
from collections import defaultdict
import ipaddress
from sqlalchemy.orm import Session

from icebreaker.db.models import Scan, Service, Finding, Target


class NetworkTopology:
    """Analyzes scan results to build network topology."""

    def __init__(self, db: Session):
        self.db = db

    def build_topology(self, scan_id: int, limit: int = None) -> Dict[str, Any]:
        """
        Build network topology from scan results for a specific scan.

        Args:
            scan_id: Scan ID (required to prevent data leaks between clients)
            limit: Limit number of nodes (for performance)

        Returns:
            Dictionary with nodes and edges for network graph
        """
        # Get the specific scan only (never mix scans from different clients)
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {
                'nodes': [],
                'edges': [],
                'stats': {
                    'total_hosts': 0,
                    'total_services': 0,
                    'total_findings': 0,
                    'high_risk_hosts': 0
                },
                'error': 'Scan not found'
            }

        # Build network graph
        nodes = {}  # host -> node data
        edges = []  # connections between hosts
        host_services = defaultdict(list)  # host -> services
        host_findings = defaultdict(list)  # host -> findings

        # First, get all alive hosts from the ping sweep (Target table)
        alive_targets = self.db.query(Target).filter(
            Target.scan_id == scan_id,
            Target.is_alive == True
        ).all()

        # Initialize nodes for all alive hosts (even those without services)
        for target in alive_targets:
            host = target.address
            nodes[host] = {
                'id': host,
                'label': host,
                'type': self._classify_host(host),
                'services': [],
                'findings': [],
                'risk_score': 0,
                'open_ports': 0
            }

        # Now add services to the nodes
        services = self.db.query(Service).filter(Service.scan_id == scan_id).all()

        for service in services:
            host = service.target

            # Add service to host
            host_services[host].append({
                'port': service.port,
                'name': service.name,
                'meta': service.meta
            })

            # If this host wasn't in alive_targets, add it now (shouldn't happen but good safety)
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
        findings = self.db.query(Finding).filter(
            Finding.scan_id == scan_id,
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
            node['color'] = self._get_risk_color(total_risk, node['open_ports'])
            # Size based on services (minimum 15 for hosts without services)
            node['size'] = max(15, min(10 + node['open_ports'] * 2, 50))

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
                'high_risk_hosts': len([n for n in nodes_list if n['risk_score'] >= 20]),
                'icmp_only_hosts': len([n for n in nodes_list if n['open_ports'] == 0])
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

    def _get_risk_color(self, risk_score: int, open_ports: int = 0) -> str:
        """Get color based on risk score and service status."""
        if risk_score >= 30:
            return '#dc2626'  # red - critical
        elif risk_score >= 15:
            return '#ea580c'  # orange - high
        elif risk_score >= 5:
            return '#d97706'  # amber - medium
        elif risk_score > 0:
            return '#65a30d'  # lime - low
        elif open_ports > 0:
            return '#0284c7'  # blue - no findings but has services
        else:
            return '#6b7280'  # gray - alive but no services (ICMP only)

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
