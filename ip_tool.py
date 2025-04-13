#!/usr/bin/env python3

import argparse
import ipaddress
import sys
import logging
from itertools import combinations

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', stream=sys.stderr)
logger = logging.getLogger(__name__)

try:
    import netifaces
except ImportError:
    logger.error("The 'netifaces' library is required. Please install it using 'pip install netifaces'.")
    sys.exit(1)

def get_local_networks() -> list[ipaddress.IPv4Network]:
    """
    Retrieves configured IPv4 networks from local network interfaces.

    Ignores loopback interfaces (like lo) and interfaces without valid
    IPv4 addresses and netmasks. It focuses on non-link-local addresses.

    Returns:
        list[ipaddress.IPv4Network]: A sorted list of unique IPv4Network objects
                                     representing the configured networks.
    """
    networks = set()
    try:
        interfaces = netifaces.interfaces()
    except Exception as e:
        logger.error(f"Failed to list network interfaces: {e}")
        return []

    for iface_name in interfaces:
        if iface_name.startswith('lo'):
            logger.debug(f"Skipping loopback interface: {iface_name}")
            continue

        try:
            if_addresses = netifaces.ifaddresses(iface_name)
        except Exception as e:
            logger.warning(f"Could not get addresses for interface {iface_name}: {e}")
            continue

        if netifaces.AF_INET in if_addresses:
            for addr_info in if_addresses[netifaces.AF_INET]:
                ip_addr = addr_info.get('addr')
                netmask = addr_info.get('netmask')

                if ip_addr and netmask:
                    try:
                        network = ipaddress.ip_network(f"{ip_addr}/{netmask}", strict=False)

                        if not network.is_loopback and not network.is_link_local:
                             networks.add(network)
                             logger.debug(f"Found network {network} on interface {iface_name}")
                        else:
                             logger.debug(f"Skipping loopback/link-local network {network} on interface {iface_name}")

                    except ValueError as e:
                        logger.warning(f"Skipping invalid address/netmask on {iface_name}: {ip_addr}/{netmask} ({e})")
                else:
                    logger.debug(f"Interface {iface_name} missing IP or netmask in AF_INET entry: {addr_info}")

    return sorted(list(networks))

def check_collisions(file_path: str) -> set[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]]:
    """
    Analyzes a file containing IP networks (one CIDR per line) and reports collisions/overlaps.

    Args:
        file_path (str): Path to the file containing IP network strings.

    Returns:
        set[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]]: A set of tuples,
            where each tuple contains two colliding IPv4Network objects.
            Returns an empty set if no collisions are found or the file is empty/invalid.
    """
    networks = []
    colliding_pairs = set()

    try:
        with open(file_path, 'r') as f:
            for line in f:
                network_str = line.strip()
                if not network_str:
                    continue
                try:
                    network = ipaddress.ip_network(network_str, strict=True)
                    if isinstance(network, ipaddress.IPv4Network):
                        networks.append(network)
                    else:
                         logger.warning(f"Skipping non-IPv4 network: '{network_str}'")
                except ValueError as e:
                    logger.warning(f"Skipping invalid network format: '{network_str}' ({e})")

    except FileNotFoundError:
        logger.error(f"Error: File not found at '{file_path}'")
        sys.exit(1)
    except IOError as e:
        logger.error(f"Error reading file '{file_path}': {e}")
        sys.exit(1)

    for net1, net2 in combinations(networks, 2):
        if net1.overlaps(net2):
            colliding_pairs.add(tuple(sorted((net1, net2), key=lambda n: n.network_address)))
            logger.debug(f"Collision detected: {net1} and {net2}")

    return colliding_pairs

def main():
    """Main function to parse command-line arguments and execute the appropriate action."""
    parser = argparse.ArgumentParser(
        description="IP Tool: Report local networks or check for collisions in a list.",
        epilog="Default action (no arguments) reports local IPv4 networks found on this system, one per line."
    )

    parser.add_argument(
        '--check-collision',
        metavar='<file_path>',
        type=str,
        help='Analyze the specified file (containing networks, one per line) for overlaps.'
    )

    args = parser.parse_args()

    if args.check_collision:
        logger.info(f"Starting collision check for file: {args.check_collision}")
        colliding_networks = check_collisions(args.check_collision)
        if colliding_networks:
            print("--- Collision Check Results ---")
            print(f"Found {len(colliding_networks)} colliding network pairs:")
            for net1, net2 in sorted(list(colliding_networks), key=lambda pair: pair[0].network_address):
                 print(f"  - {net1} overlaps with {net2}")
            print("-------------------------------")
            sys.exit(1)
        else:
            print("--- Collision Check Results ---")
            print("No colliding networks found.")
            print("-------------------------------")
            sys.exit(0)
    else:
        logger.info("Reporting local IPv4 networks...")
        local_networks = get_local_networks()
        if not local_networks:
             logger.warning("No usable local IPv4 networks found.")
        for network in local_networks:
            print(network)
        sys.exit(0)

if __name__ == "__main__":
    main()
