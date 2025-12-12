import pytest
from icebreaker.core.util import validate_target


def test_validate_ipv4():
    """Test IPv4 address validation."""
    assert validate_target("192.168.1.1") is True
    assert validate_target("10.0.0.1") is True
    assert validate_target("255.255.255.255") is True


def test_validate_invalid_ipv4():
    """Test invalid IPv4 addresses."""
    assert validate_target("256.1.1.1") is False
    assert validate_target("192.168.1") is False
    assert validate_target("192.168.1.1.1") is False


def test_validate_hostname():
    """Test hostname validation."""
    assert validate_target("example.com") is True
    assert validate_target("sub.example.com") is True
    assert validate_target("test-server.local") is True
    assert validate_target("localhost") is True


def test_validate_invalid_hostname():
    """Test invalid hostnames."""
    assert validate_target("") is False
    assert validate_target("-example.com") is False  # starts with hyphen
    assert validate_target("example-.com") is False  # ends with hyphen
    assert validate_target("ex ample.com") is False  # contains space


def test_validate_ipv6():
    """Test IPv6 address validation."""
    assert validate_target("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert validate_target("::1") is True


def test_validate_edge_cases():
    """Test edge cases."""
    assert validate_target("a" * 254) is False  # too long
    assert validate_target("..") is False  # invalid
    assert validate_target("192.168.1.1;rm -rf") is False  # injection attempt
