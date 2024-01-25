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

def anonymize_ipv4(ip_address):
    octets = ip_address.split('.')
    # Keep only the first two octets and replace the last two octets with "XXX"
    anonymized_octets = octets[:2] + ['XXX', 'XXX']
    return '.'.join(anonymized_octets)

def anonymize_ipv6(ip_address):
    groups = ip_address.split(':')
    # Keep only the first two groups and replace the remaining groups with "XXXX"
    anonymized_groups = groups[:2] + ['XXXX'] * (8 - len(groups))
    return ':'.join(anonymized_groups)

def anonymize_ip_addresses(content, geolite_database):
    # Regular expression pattern to match IPv4 and IPv6 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'

    anonymized_content = re.sub(ip_pattern, lambda match: anonymize_ipv4(match.group()) if '.' in match.group() else anonymize_ipv6(match.group()), content)

    # Create a Reader object for the GeoLite2 database
    reader = Reader(geolite_database)

    # Find country information for each IP address and replace it with a placeholder
    def replace_ip_with_country(match):
        ip_address = match.group()
        try:
            response = reader.country(ip_address)
            country_code = response.country.iso_code
            return f'[{country_code}]'
        except:
            return match.group()

    anonymized_content = re.sub(ip_pattern, replace_ip_with_country, anonymized_content)

    # Close the GeoLite2 reader
    reader.close()

    return anonymized_content

# Set up logging
# logging.basicConfig(filename='anonymize.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Check command line arguments
if len(sys.argv) > 1:
    input_file = sys.argv[1]
else:
    logging.error("Please provide an input file or use stdin.")
    sys.exit(1)

geolite_database = '/usr/local/share/GeoIP/GeoLite2-Country.mmdb'

# Read input content
try:
    with open(input_file, 'r') as file:
        content = file.read()
except Exception as e:
    logging.error(f"An error occurred while reading the input file: {str(e)}")
    sys.exit(1)

# Anonymize IP addresses
try:
    anonymized_content = anonymize_ip_addresses(content, geolite_database)

    # Create a temporary file to write the anonymized content
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    temp_filename = temp_file.name

    # Write the anonymized content to the temporary file
    temp_file.write(anonymized_content)
    temp_file.close()

    # Replace the input file with the anonymized content
    shutil.move(temp_filename, input_file)

    logging.info(f"Anonymized IP addresses in {input_file} with preserved country information.")
except Exception as e:
    logging.error(f"An error occurred while anonymizing IP addresses: {str(e)}")

