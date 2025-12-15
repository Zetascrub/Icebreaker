"""
Example Plugin: SSH Weak Cipher Detection

This plugin checks SSH servers for weak/deprecated ciphers (CBC mode ciphers).

Variables injected at runtime:
- target: IP address or hostname
- port: Port number (e.g., 22)
- service: Service name (e.g., "ssh")
- banner: SSH banner if captured

Plugin must define a check() function that returns:
{
    'findings': [
        {
            'title': str,
            'description': str,
            'severity': str,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            'recommendation': str,
            'confidence': float,  # 0.0-1.0
            'raw_output': str,  # Optional: raw command output
            'references': list,  # Optional: reference URLs
        }
    ]
}
"""
import socket
import re


def check():
    """
    Check SSH server for weak ciphers.

    Uses the injected 'target' and 'port' variables.
    """
    findings = []

    try:
        # Connect to SSH server and get supported ciphers
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # Send SSH protocol version
        sock.sendall(b"SSH-2.0-OpenSSH_Check\r\n")

        # Read banner
        response = sock.recv(4096).decode('utf-8', errors='ignore')

        # Close connection
        sock.close()

        # Simple check for CBC ciphers in banner (this is a simplified example)
        # In a real implementation, you would do a full SSH handshake to enumerate ciphers
        weak_ciphers = ['cbc', '3des', 'arcfour', 'rc4']
        detected_weak = []

        for cipher in weak_ciphers:
            if cipher in response.lower():
                detected_weak.append(cipher)

        # If weak ciphers detected or SSH version is old
        ssh_version = None
        version_match = re.search(r'SSH-([\d.]+)', response)
        if version_match:
            ssh_version = version_match.group(1)

        # Check for SSH-1.x (very weak)
        if ssh_version and ssh_version.startswith('1.'):
            findings.append({
                'title': 'SSH Protocol Version 1 Enabled',
                'description': f'The SSH server at {target}:{port} supports SSH protocol version 1, which is deprecated and insecure.',
                'severity': 'CRITICAL',
                'recommendation': 'Disable SSH protocol version 1 support. Update sshd_config to only allow Protocol 2.',
                'confidence': 1.0,
                'raw_output': response,
                'references': [
                    'https://www.ssh.com/academy/ssh/protocol',
                    'https://cwe.mitre.org/data/definitions/327.html'
                ]
            })

        # Check for weak ciphers (CBC mode)
        if detected_weak:
            findings.append({
                'title': 'SSH Server Supports Weak Ciphers',
                'description': f'The SSH server at {target}:{port} supports deprecated CBC mode ciphers: {", ".join(detected_weak)}. CBC mode ciphers are vulnerable to plaintext recovery attacks.',
                'severity': 'HIGH',
                'recommendation': 'Disable CBC mode ciphers in sshd_config. Use only secure ciphers like chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com.',
                'confidence': 0.7,  # Lower confidence since we're doing basic banner checking
                'raw_output': response,
                'references': [
                    'https://www.openssh.com/security.html',
                    'https://nvd.nist.gov/vuln/detail/CVE-2008-5161'
                ]
            })

        # If banner contains version info, add informational finding
        if banner and not findings:
            findings.append({
                'title': 'SSH Banner Information',
                'description': f'SSH server version detected: {banner}',
                'severity': 'INFO',
                'recommendation': 'Consider hiding detailed version information in SSH banner to prevent information disclosure.',
                'confidence': 1.0,
                'raw_output': banner
            })

    except socket.timeout:
        # Connection timeout - service might not be SSH
        pass
    except ConnectionRefusedError:
        # Port closed
        pass
    except Exception as e:
        # Other errors - don't create findings for connection errors
        pass

    return {'findings': findings}


# Metadata for this plugin (not executed, just for documentation)
PLUGIN_METADATA = {
    'plugin_id': 'PLUGIN-SSH-001',
    'name': 'SSH Weak Cipher Detection',
    'description': 'Detects SSH servers using weak or deprecated ciphers (CBC mode)',
    'author': 'Icebreaker Security Team',
    'version': '1.0.0',
    'target_services': ['ssh'],
    'target_ports': [22, 2222],  # Common SSH ports
    'required_variables': ['target', 'port'],
    'timeout_seconds': 30,
    'tags': ['ssh', 'cipher', 'crypto', 'cbc'],
    'severity': 'HIGH'  # Default severity if check passes
}
