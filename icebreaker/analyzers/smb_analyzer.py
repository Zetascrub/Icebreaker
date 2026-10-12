"""
SMB analyzer — unauthenticated SMB service detection and security checks.

Performs a raw SMB2 negotiate and optional SMBv1 probe to discover:
  - Whether the service is SMB (port 445)
  - Whether SMB signing is required (MEDIUM if not)
  - Supported SMB dialects (2.0.2 / 2.1 / 3.0 / 3.0.2 / 3.1.1)
  - Whether SMBv1 is still enabled (HIGH if so)
  - Basic server info from NTLMSSP challenge

Mirrors the following Nessus plugins (all uncredentialed):
  - 11011   Microsoft Windows SMB Service Detection
  - 57608   SMB Signing not required
  - 56211   Microsoft Windows SMB Versions Supported (remote check)
  - 100871  Microsoft Windows SMB2 and SMB3 Dialects Supported (remote check)
  - 96982   Server Message Block (SMB) Protocol Version 1 Enabled (uncredentialed check)
  - 10785   Microsoft Windows SMB NativeLanManager Remote System Information Disclosure
  - 26920   Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure
"""
from __future__ import annotations

import asyncio
import struct
from typing import Dict, List, Optional, Tuple

from icebreaker.core.models import Finding, RunContext, Service

# SMB magic bytes
_SMB2_MAGIC = b"\xfeSMB"
_SMB1_MAGIC = b"\xffSMB"

# SMB2 SecurityMode flags
_SIGNING_ENABLED  = 0x01
_SIGNING_REQUIRED = 0x02

# SMB2 dialect revisions (little-endian wire value)
_DIALECTS: Dict[int, str] = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

# NTLMSSP constants
_NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
_NTLMSSP_TYPE1 = 1
_NTLMSSP_TYPE2 = 2


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _netbios(payload: bytes) -> bytes:
    """Wrap *payload* in a NetBIOS Session Message header."""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_negotiate_request() -> bytes:
    """Build a minimal SMB2 NEGOTIATE request."""
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]

    body = struct.pack(
        "<HHHHI",
        36,            # StructureSize (must be 36)
        len(dialects), # DialectCount
        1,             # SecurityMode: signing enabled
        0,             # Reserved
        0x7F,          # Capabilities
    )
    body += b"\x00" * 16  # ClientGuid (random not needed for passive probe)
    body += struct.pack("<IHH", 0, 0, 0)  # NegContextOffset, Count, Reserved2
    body += struct.pack(f"<{len(dialects)}H", *dialects)

    header = (
        _SMB2_MAGIC
        + struct.pack("<HH", 64, 0)   # StructureSize, CreditCharge
        + struct.pack("<I", 0)        # Status
        + struct.pack("<HH", 0, 0xFFFF)  # Command (NEGOTIATE=0), CreditRequest
        + struct.pack("<II", 0, 0)    # Flags, NextCommand
        + struct.pack("<Q", 0)        # MessageID
        + struct.pack("<II", 0, 0)    # Reserved, TreeID
        + struct.pack("<Q", 0)        # SessionID
        + b"\x00" * 16               # Signature
    )
    return _netbios(header + body)


def _smb1_negotiate_request() -> bytes:
    """Build a minimal SMBv1 NEGOTIATE request (NT LM 0.12 only)."""
    dialect = b"\x02NT LM 0.12\x00"
    body = b"\x00" + struct.pack("<H", len(dialect)) + dialect
    header = (
        _SMB1_MAGIC
        + b"\x72"               # Command: NEGOTIATE
        + b"\x00\x00\x00\x00"   # Status
        + b"\x18"               # Flags
        + b"\x01\x28"           # Flags2
        + b"\x00\x00"           # PIDHigh
        + b"\x00" * 8           # SecurityFeatures
        + b"\x00\x00"           # Reserved
        + b"\xff\xff"           # TID
        + b"\x01\x00"           # PID
        + b"\x00\x00"           # UID
        + b"\x01\x00"           # MID
    )
    return _netbios(header + body)


def _ntlmssp_type1_request() -> bytes:
    """
    Build an SMB2 SESSION_SETUP request containing an NTLMSSP NEGOTIATE (type 1)
    message.  Used to solicit a type-2 CHALLENGE from the server, which contains
    the target name and NetBIOS computer/domain name.
    """
    # NTLMSSP NEGOTIATE message (type 1)
    ntlmssp = (
        _NTLMSSP_SIGNATURE
        + struct.pack("<I", _NTLMSSP_TYPE1)  # MessageType = 1
        + struct.pack("<I", 0x60088215)      # NegotiateFlags (standard set)
        + struct.pack("<HHI", 0, 0, 0)       # DomainName (empty)
        + struct.pack("<HHI", 0, 0, 0)       # Workstation (empty)
    )
    # Wrap in SPNEGO (minimal — just NTLMSSP OID + token)
    spnego = (
        b"\x60"  # SEQUENCE
        + _ber_len(
            b"\x06\x06\x2b\x06\x01\x05\x05\x02"  # SPNEGO OID
            + b"\xa0" + _ber_len(
                b"\x30" + _ber_len(
                    b"\xa2" + _ber_len(ntlmssp)
                )
            )
        )
    )
    # SMB2 SESSION_SETUP request body
    body = struct.pack(
        "<HBBIHhI",
        25,   # StructureSize
        0,    # Flags
        0,    # SecurityMode (client)
        0,    # Capabilities
        0,    # Channel
        0,    # SecurityBufferOffset (relative to body start = 25)
        0,    # PreviousSessionId
    )
    # Patch security buffer offset/length
    sec_buf_offset = 64 + 25 - 1  # SMB2 header (64) + body fixed part (25), minus 1 for alignment
    body = struct.pack(
        "<HBBIHHi",
        25,               # StructureSize
        0,                # Flags
        1,                # SecurityMode: signing enabled
        0x7F,             # Capabilities
        0,                # Channel
        64 + 24,          # SecurityBufferOffset (64 header + 24 body bytes before buf)
        0,                # PreviousSessionId (i = signed int)
    )
    # Actually just use a simple fixed offset
    body = (
        struct.pack("<H", 25)   # StructureSize
        + b"\x00"               # Flags
        + b"\x01"               # SecurityMode
        + struct.pack("<I", 0x7F)  # Capabilities
        + struct.pack("<I", 0)  # Channel
        + struct.pack("<H", 64 + 24)  # SecurityBufferOffset
        + struct.pack("<H", len(spnego))  # SecurityBufferLength
        + struct.pack("<Q", 0)  # PreviousSessionId
    )
    body += spnego

    header = (
        _SMB2_MAGIC
        + struct.pack("<HH", 64, 1)   # StructureSize, CreditCharge
        + struct.pack("<I", 0)        # Status
        + struct.pack("<HH", 1, 0xFFFF)  # Command (SESSION_SETUP=1), CreditRequest
        + struct.pack("<II", 0, 0)    # Flags, NextCommand
        + struct.pack("<Q", 1)        # MessageID
        + struct.pack("<II", 0, 0)    # Reserved, TreeID
        + struct.pack("<Q", 0)        # SessionID
        + b"\x00" * 16               # Signature
    )
    return _netbios(header + body)


def _ber_len(data: bytes) -> bytes:
    """BER-encode the length prefix for *data* and return prefix + data."""
    n = len(data)
    if n < 0x80:
        return bytes([n]) + data
    elif n < 0x100:
        return bytes([0x81, n]) + data
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF]) + data


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def _recv_netbios(sock) -> Optional[bytes]:
    """Read one NetBIOS-framed message from *sock*.  Returns payload or None."""
    try:
        hdr = _recv_exact(sock, 4)
        if not hdr:
            return None
        length = int.from_bytes(hdr[1:], "big")
        if length == 0 or length > 0x200000:  # sanity: max 2 MB
            return None
        return _recv_exact(sock, length)
    except Exception:
        return None


def _recv_exact(sock, n: int) -> Optional[bytes]:
    """Read exactly *n* bytes from *sock*, returning None on EOF/error."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _parse_smb2_negotiate_response(payload: bytes) -> Optional[Dict]:
    """
    Parse an SMB2 NEGOTIATE response payload (after NetBIOS header).
    Returns a dict with keys: security_mode, dialect_revision, server_guid.
    """
    if len(payload) < 64 + 6:
        return None
    if payload[:4] != _SMB2_MAGIC:
        return None
    status  = struct.unpack_from("<I", payload, 8)[0]   # Status at offset 8
    command = struct.unpack_from("<H", payload, 12)[0]  # Command at offset 12
    if command != 0 or status != 0:  # command=NEGOTIATE(0), status=SUCCESS(0)
        return None
    # Body starts at offset 64
    body = payload[64:]
    if len(body) < 10:
        return None
    struct_size, security_mode, dialect_revision = struct.unpack_from("<HHH", body, 0)
    return {
        "security_mode": security_mode,
        "dialect_revision": dialect_revision,
    }


def _extract_ntlmssp_challenge(payload: bytes) -> Optional[Dict]:
    """
    Given an SMB2 SESSION_SETUP response payload, extract the NTLMSSP CHALLENGE
    (type-2 message) and return target_name and computer_name if present.
    """
    if len(payload) < 64 + 8:
        return None
    if payload[:4] != _SMB2_MAGIC:
        return None
    # Body starts at 64; security buffer offset/length at body+4
    body = payload[64:]
    if len(body) < 10:
        return None
    sec_buf_offset = struct.unpack_from("<H", body, 4)[0]
    sec_buf_length = struct.unpack_from("<H", body, 6)[0]
    if sec_buf_offset + sec_buf_length > len(payload):
        return None
    sec_buf = payload[sec_buf_offset: sec_buf_offset + sec_buf_length]

    # Find NTLMSSP signature anywhere in the buffer (may be wrapped in SPNEGO)
    idx = sec_buf.find(_NTLMSSP_SIGNATURE)
    if idx < 0:
        return None
    ntlmssp = sec_buf[idx:]
    if len(ntlmssp) < 56:
        return None

    msg_type = struct.unpack_from("<I", ntlmssp, 8)[0]
    if msg_type != _NTLMSSP_TYPE2:
        return None

    # TargetName field at offset 12
    target_name_len    = struct.unpack_from("<H", ntlmssp, 12)[0]
    target_name_offset = struct.unpack_from("<I", ntlmssp, 16)[0]

    result = {}
    if target_name_offset + target_name_len <= len(ntlmssp):
        try:
            result["target_name"] = ntlmssp[target_name_offset: target_name_offset + target_name_len].decode("utf-16-le", errors="replace")
        except Exception:
            pass

    # TargetInfo at offset 40
    if len(ntlmssp) >= 48:
        target_info_len    = struct.unpack_from("<H", ntlmssp, 40)[0]
        target_info_offset = struct.unpack_from("<I", ntlmssp, 44)[0]
        if target_info_offset + target_info_len <= len(ntlmssp):
            ti = ntlmssp[target_info_offset: target_info_offset + target_info_len]
            # Parse AvPair list
            pos = 0
            while pos + 4 <= len(ti):
                av_id  = struct.unpack_from("<H", ti, pos)[0]
                av_len = struct.unpack_from("<H", ti, pos + 2)[0]
                av_val = ti[pos + 4: pos + 4 + av_len]
                pos += 4 + av_len
                if av_id == 0x0001:  # MsvAvNbComputerName
                    try:
                        result["nb_computer_name"] = av_val.decode("utf-16-le", errors="replace")
                    except Exception:
                        pass
                elif av_id == 0x0002:  # MsvAvNbDomainName
                    try:
                        result["nb_domain_name"] = av_val.decode("utf-16-le", errors="replace")
                    except Exception:
                        pass
                elif av_id == 0x0000:  # MsvAvEOL
                    break
    return result if result else None


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class SMBAnalyzer:
    """
    Unauthenticated SMB service detection and security checks.
    Runs against any service on port 445.
    """

    id = "smb_analyzer"

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        if service.port != 445:
            return []

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._probe, service)

    def _probe(self, service: Service) -> List[Finding]:
        findings: List[Finding] = []
        target = service.target

        # ------------------------------------------------------------------
        # 1. SMB2 NEGOTIATE — service detection + signing + dialect
        # ------------------------------------------------------------------
        smb2_result = self._smb2_negotiate(target)

        if smb2_result is None:
            # Could not connect or parse — not an SMB service (or filtered)
            return []

        security_mode    = smb2_result["security_mode"]
        dialect_revision = smb2_result["dialect_revision"]
        signing_required = bool(security_mode & _SIGNING_REQUIRED)
        signing_enabled  = bool(security_mode & _SIGNING_ENABLED)

        # Service detection (INFO)
        findings.append(Finding(
            id=f"smb.service.{target}.445",
            title="Microsoft Windows SMB Service Detection",
            severity="INFO",
            target=target,
            port=445,
            tags=["smb", "service-detection"],
            description="An SMB (Server Message Block) service was detected on this port.",
            details={"security_mode": security_mode},
        ))

        # SMB signing check (MEDIUM if not required)
        if not signing_required:
            findings.append(Finding(
                id=f"smb.signing.{target}.445",
                title="SMB Signing not required",
                severity="MEDIUM",
                target=target,
                port=445,
                tags=["smb", "signing", "relay-attack"],
                description=(
                    "Signing is not required on the remote SMB server. An unauthenticated, "
                    "remote attacker can exploit this to conduct man-in-the-middle attacks "
                    "against the SMB server."
                ),
                impact=(
                    "Without SMB signing, attackers on the network can relay NTLM credentials "
                    "to authenticate to other services (NTLM relay attacks), potentially gaining "
                    "access to additional hosts."
                ),
                recommendation=(
                    "Enable and require SMB signing. On Windows: set "
                    "'Microsoft network server: Digitally sign communications (always)' to Enabled "
                    "via Group Policy. On Samba: add 'server signing = mandatory' to smb.conf."
                ),
                references=["CVE-1999-0519", "CWE-294"],
                details={
                    "security_mode": security_mode,
                    "signing_enabled": signing_enabled,
                    "signing_required": signing_required,
                },
            ))

        # Dialect detection (INFO)
        selected_dialect = _DIALECTS.get(dialect_revision, f"Unknown (0x{dialect_revision:04x})")
        if dialect_revision >= 0x0202:
            # Report supported SMB2/3 dialects
            supported = [name for rev, name in sorted(_DIALECTS.items()) if rev <= dialect_revision]
            findings.append(Finding(
                id=f"smb.dialects_smb2.{target}.445",
                title="Microsoft Windows SMB2 and SMB3 Dialects Supported (remote check)",
                severity="INFO",
                target=target,
                port=445,
                tags=["smb", "smb2", "smb3", "dialect"],
                description=(
                    f"The remote SMB server supports the following SMB2/3 dialects: "
                    f"{', '.join(supported)}. The highest negotiated dialect is {selected_dialect}."
                ),
                details={"selected_dialect": selected_dialect, "supported_dialects": supported},
            ))

        # ------------------------------------------------------------------
        # 2. SMBv1 probe
        # ------------------------------------------------------------------
        smb1_supported = self._smb1_probe(target)
        if smb1_supported:
            findings.append(Finding(
                id=f"smb.smb1.{target}.445",
                title="Server Message Block (SMB) Protocol Version 1 Enabled (uncredentialed check)",
                severity="HIGH",
                target=target,
                port=445,
                tags=["smb", "smb1", "legacy"],
                description=(
                    "The remote SMB server supports SMBv1, which is a legacy protocol with "
                    "known critical vulnerabilities including EternalBlue (MS17-010, used by WannaCry "
                    "and NotPetya) and other remotely exploitable flaws."
                ),
                impact=(
                    "SMBv1 is exploited by numerous worm-like attacks. Microsoft has recommended "
                    "disabling SMBv1 since 2014 and it is disabled by default in Windows 10 1709+."
                ),
                recommendation=(
                    "Disable SMBv1 immediately. On Windows: "
                    "'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. "
                    "On Samba: add 'min protocol = SMB2' to smb.conf."
                ),
                references=["CVE-2017-0144", "MS17-010", "CWE-1188"],
            ))

        # SMB versions supported summary
        version_list = ["SMBv1"] if smb1_supported else []
        version_list += [name for rev, name in sorted(_DIALECTS.items()) if rev <= dialect_revision]
        findings.append(Finding(
            id=f"smb.versions.{target}.445",
            title="Microsoft Windows SMB Versions Supported (remote check)",
            severity="INFO",
            target=target,
            port=445,
            tags=["smb", "versions"],
            description=f"The remote SMB server supports: {', '.join(version_list)}.",
            details={"versions": version_list},
        ))

        # ------------------------------------------------------------------
        # 3. NTLMSSP handshake — server/domain name disclosure
        # ------------------------------------------------------------------
        ntlmssp_info = self._ntlmssp_handshake(target)
        if ntlmssp_info:
            parts = []
            if ntlmssp_info.get("nb_computer_name"):
                parts.append(f"Computer: {ntlmssp_info['nb_computer_name']}")
            if ntlmssp_info.get("nb_domain_name"):
                parts.append(f"Domain: {ntlmssp_info['nb_domain_name']}")
            if ntlmssp_info.get("target_name"):
                parts.append(f"Target: {ntlmssp_info['target_name']}")

            if parts:
                findings.append(Finding(
                    id=f"smb.ntlmssp.{target}.445",
                    title="Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure",
                    severity="INFO",
                    target=target,
                    port=445,
                    tags=["smb", "ntlmssp", "info-disclosure"],
                    description=(
                        "The remote SMB server disclosed host and/or domain information via "
                        f"the NTLMSSP authentication handshake: {'; '.join(parts)}."
                    ),
                    details=ntlmssp_info,
                ))
                findings.append(Finding(
                    id=f"smb.netbios_info.{target}.445",
                    title="Windows NetBIOS / SMB Remote Host Information Disclosure",
                    severity="INFO",
                    target=target,
                    port=445,
                    tags=["smb", "netbios", "info-disclosure"],
                    description=(
                        "The remote SMB server disclosed NetBIOS host information: "
                        + "; ".join(parts)
                    ),
                    details=ntlmssp_info,
                ))

        return findings

    # -----------------------------------------------------------------------
    # Low-level SMB helpers (synchronous, run in executor)
    # -----------------------------------------------------------------------

    def _smb2_negotiate(self, host: str, port: int = 445, timeout: float = 5.0) -> Optional[Dict]:
        """Send SMB2 negotiate, return parsed result or None."""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(_smb2_negotiate_request())
            payload = _recv_netbios(sock)
            sock.close()
            if payload:
                return _parse_smb2_negotiate_response(payload)
        except Exception:
            pass
        return None

    def _smb1_probe(self, host: str, port: int = 445, timeout: float = 5.0) -> bool:
        """Return True if SMBv1 negotiate gets a valid SMBv1 response."""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(_smb1_negotiate_request())
            payload = _recv_netbios(sock)
            sock.close()
            if payload and payload[:4] == _SMB1_MAGIC:
                return True
        except Exception:
            pass
        return False

    def _ntlmssp_handshake(self, host: str, port: int = 445, timeout: float = 5.0) -> Optional[Dict]:
        """
        Perform SMB2 negotiate + SESSION_SETUP with NTLMSSP type-1,
        then parse the NTLMSSP type-2 challenge for server/domain info.
        """
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Round 1: SMB2 negotiate
            sock.sendall(_smb2_negotiate_request())
            neg_payload = _recv_netbios(sock)
            if not neg_payload or neg_payload[:4] != _SMB2_MAGIC:
                sock.close()
                return None

            # Round 2: SESSION_SETUP with NTLMSSP type-1
            sock.sendall(_ntlmssp_type1_request())
            ss_payload = _recv_netbios(sock)
            sock.close()
            if ss_payload:
                return _extract_ntlmssp_challenge(ss_payload)
        except Exception:
            pass
        return None
