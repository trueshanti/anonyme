#!/usr/bin/env python3

"""
    Anonymize IP addresses in a file while preserving country information.
    This script uses MaxMind GeoLite2 database for country information.

    Copyright (C) 2024 Christoph Resch <shanti@mojo.cc>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import re
import logging
import tempfile
import shutil
import os
from geoip2.database import Reader
import argparse

# List of IP addresses to skip anonymizing
excluded_ips = [
    "127.0.0.1", "127.0.0.2", "::1/128",
    # Server IPs
    "138.201.251.60", "2a01:4f8:173:2203::2",
    "148.251.207.64", "2a01:4f8:173:2203::64",
    "148.251.207.65", "2a01:4f8:173:2203::65",
    "148.251.207.66", "2a01:4f8:173:2203::66",
    "148.251.207.67", "2a01:4f8:173:2203::67",
    "148.251.207.68", "2a01:4f8:173:2203::68",
    "148.251.207.69", "2a01:4f8:173:2203::69",
    "148.251.207.70", "2a01:4f8:173:2203::70",
    "148.251.207.71", "2a01:4f8:173:2203::71",
    "148.251.207.72", "2a01:4f8:173:2203::72",
    "148.251.207.73", "2a01:4f8:173:2203::73",
    "148.251.207.74", "2a01:4f8:173:2203::74",
    "148.251.207.75", "2a01:4f8:173:2203::75",
    "148.251.207.76", "2a01:4f8:173:2203::76",
    "148.251.207.77", "2a01:4f8:173:2203::77",
    "148.251.207.78", "2a01:4f8:173:2203::78",
    "148.251.207.79", "2a01:4f8:173:2203::79",
    "fe80::aaa1:59ff:fea2:96cc"
]

def is_private_ip(ip_address):
    """Check if an IP address is in a private/local range."""
    if '.' in ip_address:  # IPv4
        octets = ip_address.split('.')
        if len(octets) != 4:
            return False
        try:
            first = int(octets[0])
            second = int(octets[1])
            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            # 127.0.0.0/8 (loopback)
            if first == 127:
                return True
        except ValueError:
            return False
    else:  # IPv6
        # fc00::/7 (Unique Local Addresses)
        if ip_address.startswith('fc') or ip_address.startswith('fd'):
            return True
        # fe80::/10 (Link-local)
        if ip_address.startswith('fe80'):
            return True
        # ::1 (loopback)
        if ip_address == '::1':
            return True
    return False

def anonymize_ipv4(ip_address):
    octets = ip_address.split('.')
    anonymized_octets = octets[:2] + ['XXX', 'XXX']
    return '.'.join(anonymized_octets)

def anonymize_ipv6(ip_address):
    # Handle compressed notation (::)
    if '::' in ip_address:
        # Keep the first two groups before ::, anonymize the rest
        parts = ip_address.split('::', 1)
        left_groups = parts[0].split(':') if parts[0] else []
        # Keep up to 2 groups from the left
        kept_groups = left_groups[:2]
        if len(kept_groups) < 2 and parts[0]:
            # If we have less than 2 groups, keep what we have
            return ':'.join(kept_groups) + '::XXXX'
        elif len(kept_groups) == 2:
            return ':'.join(kept_groups) + '::XXXX'
        else:
            return '::XXXX'
    else:
        # Full format without compression
        groups = ip_address.split(':')
        anonymized_groups = groups[:2] + ['XXXX'] * (len(groups) - 2)
        return ':'.join(anonymized_groups)

def anonymize_ip_addresses(content, geolite_database, replace_with_country_code=False):
    # IPv4 pattern
    ipv4_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    # IPv6 pattern (handles :: compression)
    ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:|:(?::[0-9a-fA-F]{1,4}){1,6}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::'
    ip_pattern = rf'\[?(?P<ip>{ipv4_pattern}|{ipv6_pattern})\]?'

    reader = Reader(geolite_database)

    def replace_ip(match):
        ip_address = match.group('ip')
        if ip_address in excluded_ips:
            return match.group()  # preserve brackets if present
        try:
            if replace_with_country_code:
                # Check if it's a private/local IP
                if is_private_ip(ip_address):
                    return '[LOCAL]'
                response = reader.country(ip_address)
                country_code = response.country.iso_code
                return f'[{country_code}]'
            elif '.' in ip_address:
                return anonymize_ipv4(ip_address)
            else:
                return anonymize_ipv6(ip_address)
        except:
            return match.group()  # return original if unable to process

    anonymized_content = re.sub(ip_pattern, replace_ip, content)
    reader.close()

    return anonymized_content

def main():
    parser = argparse.ArgumentParser(
        description='Anonymize IP addresses in log files with GeoLite2 country information.',
        epilog='''
Examples:
  %(prog)s /var/log/access.log                    # Anonymize IPs in single file
  %(prog)s /var/log/*.log                         # Anonymize IPs in multiple files
  %(prog)s /var/log/access.log -CC                # Replace IPs with country codes
  %(prog)s /var/log/access.log -l                 # Enable logging to anonymize.log
  %(prog)s /var/log/access.log -CC -l             # Country codes with logging
  %(prog)s /var/log/mail.log /var/log/auth.log -l # Multiple files with logging

Anonymization format:
  IPv4: 192.168.1.100 → 192.168.XXX.XXX
  IPv6: 2a01:4f8:173:2203::65 → 2a01:4f8::XXXX
  Country code (-CC): 203.0.113.42 → [US], 192.168.1.100 → [LOCAL]
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input_file', metavar='input_file', type=str, nargs='+', 
                        help='one or more log files to anonymize')
    parser.add_argument('-CC', action='store_true', 
                        help='replace IP addresses with country codes instead of anonymizing')
    parser.add_argument('-l', '--log', action='store_true', 
                        help='enable logging to anonymize.log file')
    args = parser.parse_args()

    if args.log:
        # Determine log file location based on first input file's directory
        try:
            first_file_dir = os.path.dirname(os.path.abspath(args.input_file[0]))
            # Check if directory is writable
            if os.access(first_file_dir, os.W_OK):
                log_file = os.path.join(first_file_dir, 'anonymize.log')
            else:
                # Fallback to current working directory
                log_file = 'anonymize.log'
        except:
            # Fallback to current working directory
            log_file = 'anonymize.log'
        
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.disable(logging.CRITICAL)

    geolite_database = '/usr/local/share/GeoIP/GeoLite2-Country.mmdb'

    for input_file in args.input_file:
        try:
            with open(input_file, 'r', encoding='utf-8', errors='replace') as file:
                content = file.read()
        except Exception as e:
            if args.log:
                logging.error(f"An error occurred while reading the input file {input_file}: {str(e)}")
            continue

        try:
            anonymized_content = anonymize_ip_addresses(content, geolite_database, replace_with_country_code=args.CC)
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
            temp_filename = temp_file.name
            temp_file.write(anonymized_content)
            temp_file.close()
            shutil.move(temp_filename, input_file)
            if args.log:
                if args.CC:
                    logging.info(f"Replaced IP addresses with country codes in {input_file}.")
                else:
                    logging.info(f"Anonymized IP addresses in {input_file}.")
        except Exception as e:
            if args.log:
                logging.error(f"An error occurred while processing IP addresses in {input_file}: {str(e)}")

if __name__ == "__main__":
    main()

