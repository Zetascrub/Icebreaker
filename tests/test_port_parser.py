import pytest
from icebreaker.core.port_parser import parse_port_spec, get_top_ports


def test_parse_single_port():
    """Test parsing a single port."""
    assert parse_port_spec("80") == [80]


def test_parse_multiple_ports():
    """Test parsing comma-separated ports."""
    assert parse_port_spec("80,443,8080") == [80, 443, 8080]


def test_parse_port_range():
    """Test parsing a port range."""
    result = parse_port_spec("8000-8003")
    assert result == [8000, 8001, 8002, 8003]


def test_parse_mixed():
    """Test parsing mixed ports and ranges."""
    result = parse_port_spec("22,80,443,8000-8002")
    assert result == [22, 80, 443, 8000, 8001, 8002]


def test_parse_with_spaces():
    """Test parsing with whitespace."""
    result = parse_port_spec("  22 , 80 , 443  ")
    assert result == [22, 80, 443]


def test_parse_invalid_port():
    """Test parsing invalid port numbers."""
    with pytest.raises(ValueError):
        parse_port_spec("0")
    with pytest.raises(ValueError):
        parse_port_spec("70000")


def test_parse_invalid_range():
    """Test parsing invalid port range."""
    with pytest.raises(ValueError):
        parse_port_spec("8080-8000")  # start > end


def test_parse_empty():
    """Test parsing empty string."""
    with pytest.raises(ValueError):
        parse_port_spec("")


def test_get_top_ports():
    """Test getting top ports."""
    top_100 = get_top_ports(100)
    assert len(top_100) == 100
    assert 80 in top_100
    assert 443 in top_100
    assert 22 in top_100
