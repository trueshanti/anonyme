# Anonyme

Anonyme is a Python script designed to anonymize IPv4 and IPv6 addresses in log files while optionally preserving country information using the MaxMind GeoLite2 database. It is primarily intended to be used in log rotation workflows, such as in the `prerotate` section of `logrotate`.

## Features

- **IPv4 and IPv6 Anonymization**: Masks parts of IP addresses to ensure privacy.
- **Country Code Replacement**: Optionally replaces IP addresses with their corresponding country codes.
- **Integration with Logrotate**: Seamlessly integrates into log rotation workflows.
- **Exclusion List**: Allows specific IP addresses to be excluded from anonymization.

## Example Usage with Logrotate

Anonyme is designed to be used in the `prerotate` section of `logrotate` configurations. Below is an example configuration:

```plaintext
/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
{
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    prerotate
        /usr/local/sbin/anonyme.py -CC $1
    endscript
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

This configuration anonymizes or replaces IP addresses with country codes in the specified log files before they are rotated.

## Requirements

- Python 3.x
- [GeoIP2](https://pypi.org/project/geoip2/) library
- MaxMind GeoLite2 Country database (`GeoLite2-Country.mmdb`)

## Installation

1. Clone the repository:
   ```bash
   git clone /path/to/anonyme.git
   cd anonyme.git
   ```

2. Install dependencies:
   ```bash
   pip install geoip2
   ```

3. Download the GeoLite2 Country database from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place it in `/usr/local/share/GeoIP/GeoLite2-Country.mmdb`.

## Usage

Run the script with the following command:

```bash
python3 anonyme.py <input_file> [-CC]
```

### Arguments

- `<input_file>`: Path to the log file to be processed.
- `-CC`: Optional flag to replace IP addresses with country codes instead of anonymizing them.

### Example

1. **Anonymize IP Addresses**:
   ```bash
   python3 anonyme.py logs/access.log
   ```

   This will anonymize all IP addresses in `access.log`.

2. **Replace IP Addresses with Country Codes**:
   ```bash
   python3 anonyme.py logs/access.log -CC
   ```

   This will replace all IP addresses in `access.log` with their corresponding country codes.

## Logging

The script logs its operations to `anonymize.log` in the current directory. This includes any errors encountered during processing.

## License

This program is licensed under the GNU General Public License v3.0. See the [LICENSE](https://www.gnu.org/licenses/gpl-3.0.html) file for more details.

## Author

Christoph Resch  
Email: shanti@mojo.cc

---

_Amused by the lameness of other "solutions," I let ChatGPT write this. One day, I really will read that book and learn to code Python properly!_

