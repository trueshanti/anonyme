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
from geoip2.database import Reader
import argparse

# List of IP addresses to skip anonymizing
excluded_ips = [
    "127.0.0.1", "127.0.0.2", "148.251.207.64", "148.251.207.65", "148.251.207.66", 
    "148.251.207.67", "148.251.207.68", "148.251.207.69", "148.251.207.70", 
    "148.251.207.71", "148.251.207.72", "148.251.207.73", "148.251.207.74", 
    "148.251.207.75", "148.251.207.76", "148.251.207.77", "148.251.207.78", 
    "148.251.207.79", "2a01:4f8:173:2203:0:0:0:2", "2a01:4f8:173:2203:0:0:0:64", 
    "2a01:4f8:173:2203:0:0:0:65", "2a01:4f8:173:2203:0:0:0:66", "2a01:4f8:173:2203:0:0:0:67", 
    "2a01:4f8:173:2203:0:0:0:68", "2a01:4f8:173:2203:0:0:0:69", "2a01:4f8:173:2203:0:0:0:70", 
    "2a01:4f8:173:2203:0:0:0:71", "2a01:4f8:173:2203:0:0:0:72", "2a01:4f8:173:2203:0:0:0:73", 
    "2a01:4f8:173:2203:0:0:0:74", "2a01:4f8:173:2203:0:0:0:75", "2a01:4f8:173:2203:0:0:0:76", 
    "2a01:4f8:173:2203:0:0:0:77", "2a01:4f8:173:2203:0:0:0:78", "2a01:4f8:173:2203:0:0:0:79"
]

def anonymize_ipv4(ip_address):
    octets = ip_address.split('.')
    anonymized_octets = octets[:2] + ['XXX', 'XXX']
    return '.'.join(anonymized_octets)

def anonymize_ipv6(ip_address):
    groups = ip_address.split(':')
    anonymized_groups = groups[:2] + ['XXXX'] * (8 - len(groups))
    return ':'.join(anonymized_groups)

def anonymize_ip_addresses(content, geolite_database, replace_with_country_code=False):
    ip_pattern = r'\[?(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\]?'

    reader = Reader(geolite_database)

    def replace_ip(match):
        ip_address = match.group('ip')
        if ip_address in excluded_ips:
            return match.group()  # preserve brackets if present
        try:
            if replace_with_country_code:
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
    parser = argparse.ArgumentParser(description='Anonymize IP addresses in a log file with GeoLite2 country information.')
    parser.add_argument('input_file', metavar='input_file', type=str, help='the input file to anonymize')
    parser.add_argument('-CC', action='store_true', help='replace IP addresses with country codes instead of anonymizing')
    args = parser.parse_args()

    logging.basicConfig(filename='anonymize.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    geolite_database = '/usr/local/share/GeoIP/GeoLite2-Country.mmdb'

    try:
        with open(args.input_file, 'r', encoding='utf-8', errors='replace') as file:
            content = file.read()
    except Exception as e:
        logging.error(f"An error occurred while reading the input file: {str(e)}")
        sys.exit(1)

    try:
        anonymized_content = anonymize_ip_addresses(content, geolite_database, replace_with_country_code=args.CC)
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        temp_filename = temp_file.name
        temp_file.write(anonymized_content)
        temp_file.close()
        shutil.move(temp_filename, args.input_file)
        if args.CC:
            logging.info(f"Replaced IP addresses with country codes in {args.input_file}.")
        else:
            logging.info(f"Anonymized IP addresses in {args.input_file}.")
    except Exception as e:
        logging.error(f"An error occurred while processing IP addresses: {str(e)}")

if __name__ == "__main__":
    main()
