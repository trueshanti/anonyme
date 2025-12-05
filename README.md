# Anonyme

Anonyme is a Python script designed to anonymize IPv4 and IPv6 addresses in log files while optionally preserving country information using the MaxMind GeoLite2 database. It is primarily intended to be used in log rotation workflows, such as in the `prerotate` section of `logrotate`.

## Features

- **IPv4 and IPv6 Anonymization**: Masks parts of IP addresses to ensure privacy (keeps first two octets/groups).
- **Country Code Replacement**: Optionally replaces IP addresses with their corresponding country codes.
- **Local IP Detection**: Automatically identifies private/local IP ranges (10.x.x.x, 192.168.x.x, etc.) and marks them as `[LOCAL]` in country code mode.
- **Multiple File Support**: Process multiple log files in a single command.
- **Compressed IPv6 Support**: Properly handles IPv6 addresses with `::` compression notation.
- **Optional Logging**: Enable detailed logging with `-l`/`--log` flag.
- **Smart Log Placement**: Logs are created in the directory of the file being processed, not in the user's home directory.
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
        /usr/local/sbin/anonyme.py $1
    endscript
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

**Note**: When using with logrotate's `sharedscripts`, the `$1` variable will expand to all log files being rotated, allowing the script to process multiple files at once.

**Important**: The `delaycompress` option is mandatory when using this script in the `prerotate` section. Without it, logrotate will compress the files before the script can anonymize them, preventing the IP address anonymization from working correctly.

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
python3 anonyme.py <input_file> [<input_file2> ...] [-CC] [-l|--log]
```

### Arguments

- `<input_file>`: Path to one or more log files to be processed. Multiple files can be specified.
- `-CC`: Optional flag to replace IP addresses with country codes instead of anonymizing them.
- `-l, --log`: Optional flag to enable logging to `anonymize.log` (created in the same directory as the first input file).

### Example

1. **Anonymize IP Addresses in a Single File**:
   ```bash
   python3 anonyme.py logs/access.log
   ```

   This will anonymize all IP addresses in `access.log`.

2. **Anonymize IP Addresses in Multiple Files**:
   ```bash
   python3 anonyme.py /var/log/mail.warn /var/log/mail.err /var/log/mail.log
   ```

   This will anonymize all IP addresses in all specified log files.

3. **Replace IP Addresses with Country Codes**:
   ```bash
   python3 anonyme.py logs/access.log -CC
   ```

   This will replace all IP addresses in `access.log` with their corresponding country codes.

4. **Enable Logging**:
   ```bash
   python3 anonyme.py /var/log/access.log -l
   ```

   This will anonymize IPs and create a log file at `/var/log/anonymize.log`.

5. **Combined Options**:
   ```bash
   python3 anonyme.py /var/log/mail.log /var/log/auth.log -CC -l
   ```

   Process multiple files with country codes and logging enabled.

### Anonymization Examples

- IPv4: `192.168.1.100` → `192.168.XXX.XXX`
- IPv6 (full): `2001:0db8:85a3:0000:0000:8a2e:0370:7334` → `2001:0db8:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX`
- IPv6 (compressed): `2a01:4f8:173:2203::65` → `2a01:4f8::XXXX`
- Country codes: `203.0.113.42` → `[US]`, `192.168.1.100` → `[LOCAL]`

## Logging

Logging is disabled by default. When enabled with the `-l` or `--log` flag, the script creates `anonymize.log` in the same directory as the first input file being processed (with fallback to the current working directory if that location is not writable). The log includes:

- Successful anonymization/replacement operations
- Errors encountered while reading or processing files
- Timestamp and log level for each entry

## License

This program is licensed under the GNU General Public License v3.0. See the [LICENSE](https://www.gnu.org/licenses/gpl-3.0.html) file for more details.

## Author

Christoph Resch  
Email: shanti@mojo.cc

---

_Amused by the lameness of other "solutions," I let ChatGPT write this. One day, I really will read that book and learn to code Python properly!_

