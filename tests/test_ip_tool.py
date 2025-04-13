import pytest
import argparse
import ipaddress
import sys
import os
import logging
from unittest.mock import patch, MagicMock, mock_open

try:
    from ip_tool import get_local_networks, check_collisions, main, netifaces
except ImportError as e:
    pytest.fail(
        f"Could not import 'ip_tool'. Ensure ip_tool.py exists in the project root "
        f"and pytest is run from there. Error: {e}"
    )

MOCK_INTERFACES = ['lo0', 'eth0', 'eth1', 'docker0', 'veth123']
MOCK_ADDRS = {
    'lo0': {
        netifaces.AF_INET: [{'addr': '127.0.0.1', 'netmask': '255.0.0.0'}],
        netifaces.AF_INET6: [{'addr': '::1', 'netmask': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'}]
    },
    'eth0': {
        netifaces.AF_INET: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0', 'broadcast': '192.168.1.255'}],
        netifaces.AF_LINK: [{'addr': '02:42:ac:11:00:02'}]
    },
    'eth1': {
        netifaces.AF_LINK: [{'addr': '02:42:ac:11:00:03'}]
    },
    'docker0': {
        netifaces.AF_INET: [{'addr': '172.17.0.1', 'netmask': '255.255.0.0', 'broadcast': '172.17.255.255'}]
    },
    'veth123': {
         netifaces.AF_INET: [{'addr': '169.254.10.20', 'netmask': '255.255.0.0'}]
    }
}

def mock_ifaddresses_func(iface):
    return MOCK_ADDRS.get(iface, {})


@patch('ip_tool.netifaces.interfaces', return_value=MOCK_INTERFACES)
@patch('ip_tool.netifaces.ifaddresses', side_effect=mock_ifaddresses_func)
def test_get_local_networks_success(mock_ifaddresses_call, mock_interfaces_call, caplog):
    """Test successful retrieval of expected networks, ignoring loopback, link-local, and interfaces without IPv4."""
    caplog.set_level(logging.DEBUG)

    expected_networks = sorted([
        ipaddress.ip_network('192.168.1.0/24'),
        ipaddress.ip_network('172.17.0.0/16')
    ])

    networks = get_local_networks()

    assert networks == expected_networks
    mock_interfaces_call.assert_called_once()
    assert mock_ifaddresses_call.call_count == len(MOCK_INTERFACES) - 1
    assert "Skipping loopback interface: lo0" in caplog.text
    assert "Skipping loopback/link-local network 169.254.0.0/16 on interface veth123" in caplog.text
    assert "Found network 192.168.1.0/24 on interface eth0" in caplog.text
    assert "Found network 172.17.0.0/16 on interface docker0" in caplog.text


def test_check_collisions_no_collision(tmp_path):
    """Test collision check with a file containing non-colliding networks."""
    file_content = """
    192.168.1.0/24
    10.0.0.0/8
    172.16.0.0/16
    """
    p = tmp_path / "networks.txt"
    p.write_text(file_content)
    collisions = check_collisions(str(p))
    assert collisions == set()

def test_check_collisions_with_overlaps(tmp_path):
    """Test collision check with various overlapping networks."""
    file_content = """
    192.168.1.0/24
    10.0.0.0/8
    192.168.1.128/25 
    10.1.0.0/16
    172.16.0.0/12
    10.1.2.0/24
    """
    p = tmp_path / "networks.txt"
    p.write_text(file_content)

    net_192_1_0_24 = ipaddress.ip_network('192.168.1.0/24')
    net_192_1_128_25 = ipaddress.ip_network('192.168.1.128/25')
    net_10_0_0_8 = ipaddress.ip_network('10.0.0.0/8')
    net_10_1_0_16 = ipaddress.ip_network('10.1.0.0/16')
    net_10_1_2_24 = ipaddress.ip_network('10.1.2.0/24')

    expected_collisions = {
        tuple(sorted((net_192_1_0_24, net_192_1_128_25), key=lambda n: n.network_address)),
        tuple(sorted((net_10_0_0_8, net_10_1_0_16), key=lambda n: n.network_address)),
        tuple(sorted((net_10_0_0_8, net_10_1_2_24), key=lambda n: n.network_address)),
        tuple(sorted((net_10_1_0_16, net_10_1_2_24), key=lambda n: n.network_address)),
    }

    collisions = check_collisions(str(p))
    assert collisions == expected_collisions