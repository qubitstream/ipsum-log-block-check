IPsum Log Block Check
=====================

A Python utility to check IP addresses (IPv4) in log files against the [IPsum blocklist](https://github.com/stamparm/ipsum).

Useful for analyzing access logs or security event logs to identify potentially malicious IP addresses and evaluate how the IPsum blocklist at the given level would block those
(for example by using [ufw-blocklist](https://github.com/poddmo/ufw-blocklist))

## Features

- Parses plain text or compressed log files (`.gz`, `.bz2`, `.lzma`)
- Extracts IPv4 addresses from log lines
- Optionally filters log entries by include / exclude search terms (case sensitive or insensitive)
- Selects the N-th IPv4 address from each line for evaluation
  (supports negative indexing)
- Checks IPs against different levels of the IPsum block list
- Supports caching of IPsum data (with optional expiration)
- Outputs a summary and top N matched IPs
- Handles log rotation: supports parsing older `.log.N(.gz|.bz2|.lzma)` files
- Memory-efficient: processes data line per line
- Optionally output as JSON to stdout

## Requirements

- Python 3.7+, so all supported versions can run this
- No third-party dependencies!

## Installation

### 1. As simple local script

Just clone the repo to a directory of your choice:

```bash
git clone https://github.com/qubitstream/ipsum-log-block-check.git
cd ipsum-log-block-check
python ipsum_log_block_check.py --help
```

### 2. As a command on UNIX, available system wide for all users

Clone the repo to `/opt/ipsum-log-block-check`, then create a symlink in `/usr/local/bin/ipsum_log_block_check.py`

Any user can the run `ipsum_log_block_check.py`, which should be available in PATH.

Of course, some python interpreter must be available.

#### Installation

```bash
sudo git clone https://github.com/qubitstream/ipsum-log-block-check.git /opt/ipsum-log-block-check && sudo chmod 755 /opt/ipsum-log-block-check/ipsum_log_block_check.py && sudo ln -s /opt/ipsum-log-block-check/ipsum_log_block_check.py /usr/local/bin/ipsum_log_block_check.py
```

#### Update

```bash
sudo git -C /opt/ipsum-log-block-check checkout -- ipsum_log_block_check.py && git -C /opt/ipsum-log-block-check pull origin master && sudo chmod 755 /opt/ipsum-log-block-check/ipsum_log_block_check.py
```

## Examples

### Basic Check

Check all IPs in a log file with default settings:

```bash
python ipsum_log_block_check.py /var/log/access.log
```

### Filter by Terms

Only check lines containing "POST" (case sensitive), "failed login" (case insensitive) but not "admin" (case insensitive):

```bash
python ipsum_log_block_check.py -S POST -s "Failed login" -x admin /var/log/auth.log
```

### Process Multiple Files

Check multiple log files including rotated versions:

```bash
python ipsum_log_block_check.py -L 5 /var/log/nginx/access.log /var/log/apache2/access.log
```

### Generate JSON Report

```bash
python ipsum_log_block_check.py --json /var/log/fail2ban.log > report.json
```

### Change IPsum Level

Use a more strict blocking level:

```bash
python ipsum_log_block_check.py --ipsum-level 1 /var/log/auth.log
```

### Complex Example

```bash
python ipsum_log_block_check.py \
  -S "Failed password" \
  -x "internal" \
  --n-th-ip -1 \
  --ipsum-level 1 \
  --top-n 10 \
  --older-logs-up-to-n 3 \
  /var/log/auth.log
```

## Output Format

### Text Output (Default)

The default output shows:

- Script parameters and input files
- Information about the IPsum list used
- Top IP addresses found (if requested)
- Statistics on blocked vs. non-blocked IPs
- Line-by-line results showing each IP and whether it would be blocked

Example output (redacted)

```
[...]
BLOCKED | XXX.XXX.XXX.XXX | XXX.XXX.XXX.XXX - - [1 [...] .0.0.0 Safari/537.36"
     OK | XXX.XXX.XXX.XXX | XXX.XXX.XXX.XXX - - [18 [...] .0.0.0 Safari/537.36"
BLOCKED | XXX.XXX.XXX.XXX | XXX.XXX.XXX.XXX - - [18 [...] .0.0.0 Safari/537.36"

__________ Params __________
IPsum list level 2 (containing 25363 IPs)
IPsum list cache file: /tmp/ipsum_log_block_check__ipsum_blocked_ips__level_2.txt
IPsum list date: 2025-04-18T00:37:23.219933
Log file(s) parsed (2):
   1. /var/log/nginx/access.log.1
   2. /var/log/nginx/access.log
Looking at IP number 1 in each line
Search term(s):
   1. +   case sensitive: POST

__________ Top 5 total IPs __________
 1. | XXX.XXX.XXX.XXX | 473x
 2. | XXX.XXX.XXX.XXX | 470x
 3. | XXX.XXX.XXX.XXX | 26x
 4. | XXX.XXX.XXX.XXX | 17x
 5. | XXX.XXX.XXX.XXX | 15x
__________ Top 5 unblocked IPs __________
 1. | XXX.XXX.XXX.XXX | 473x
 2. | XXX.XXX.XXX.XXX | 470x
 3. | XXX.XXX.XXX.XXX | 26x
 4. | XXX.XXX.XXX.XXX | 12x
 5. | XXX.XXX.XXX.XXX | 7x
__________ Top 5 blocked IPs __________
 1. | XXX.XXX.XXX.XXX | 17x
 2. | XXX.XXX.XXX.XXX | 15x
 3. | XXX.XXX.XXX.XXX | 14x
 4. | XXX.XXX.XXX.XXX | 13x
 5. | XXX.XXX.XXX.XXX | 13x

__________ Results __________
Using IPsum list level 2 (25363 IPs):
   49.45% entries would be blocked (1265 out of 2558, unblocked: 1293)
   63.33% unique IPs would be blocked (342 out of 540, unblocked: 198)
```

### JSON Output

When using the `--json` flag, outputs a structured JSON document containing:

- All relevant input parameters
- Processing details
- Comprehensive results including counts and statistics
- Top IPs by frequency
- Note: Lists of IPs will be set to null in the JSON output for brevity

Example (redacted):

```bash
python ipsum_log_block_check.py /var/log/nginx/access.log --older-logs-up-to-n 5 --ipsum-level 1 -S POST -x test --json
```

```json
{
    "params": {
        "input_file": [
            "/var/log/nginx/access.log"
        ],
        "older_logs_up_to_n": 5,
        "process_by_mtime": false,
        "include_term_case_insensitive": [],
        "include_term_case_sensitive": [
            "POST"
        ],
        "exclude_term_case_insensitive": [
            "test"
        ],
        "exclude_term_case_sensitive": [],
        "n_th_ip": 1,
        "ipsum_level": 1,
        "ipsum_max_age": 60,
        "no_ok": true,
        "no_blocked": true,
        "top_n": 2
    },
    "processed": {
        "hostname": "machina",
        "user": "root",
        "platform": "Linux-6.1.0-32-amd64-x86_64-with-glibc2.36",
        "run_at": "2025-04-22T00:15:31.191540+02:00",
        "input_paths": [
            "/var/log/nginx/access.log.5.gz",
            "/var/log/nginx/access.log.4.gz",
            "/var/log/nginx/access.log.3.gz",
            "/var/log/nginx/access.log.2.gz",
            "/var/log/nginx/access.log.1",
            "/var/log/nginx/access.log"
        ],
        "search_terms": [
            {
                "term": "POST",
                "kind": "include",
                "case_sensitive": true
            },
            {
                "term": "test",
                "kind": "exclude",
                "case_sensitive": false
            }
        ],
        "blacklisted_ips": null,
        "blacklisted_count": 173510,
        "ipsum_datetime": "2025-04-22T00:12:53.670859+02:00",
        "ipsum_cache_file": "/tmp/ipsum_log_block_check__root/ipsum_blocked_ips__level_1.txt"
    },
    "results": {
        "entries": {
            "total": null,
            "total_count": 231,
            "blocked": null,
            "blocked_count": 62,
            "unblocked": null,
            "unblocked_count": 169,
            "blocked_ratio": 0.2683982683982684
        },
        "ips": {
            "total": null,
            "total_count": 66,
            "blocked": null,
            "blocked_count": 20,
            "unblocked": null,
            "unblocked_count": 46,
            "blocked_ratio": 0.30303030303030304,
            "top": {
                "n": 2,
                "total": [
                    {
                        "ip": "XXX.XXX.XXX.XXX",
                        "count": 18
                    },
                    {
                        "ip": "XXX.XXX.XXX.XXX",
                        "count": 16
                    }
                ],
                "blocked": [
                    {
                        "ip": "XXX.XXX.XXX.XXX",
                        "count": 18
                    },
                    {
                        "ip": "XXX.XXX.XXX.XXX",
                        "count": 8
                    }
                ],
                "unblocked": [
                    {
                        "ip": "XXX.XXX.XXX.XXX",
                        "count": 16
                    },
                    {
                        "ip": "XXX.XXX.XXX.XXX",
                        "count": 12
                    }
                ]
            }
        }
    }
}
```

## Help / Usage

```bash
python ipsum_log_block_check.py --help
```

```
usage: ipsum_log_block_check.py [-h] [--encoding ENCODING] [-L NUMBER]
                                [--process-by-mtime] [-s TERM] [-S TERM]
                                [-x TERM] [-X TERM] [-n N_TH_IP]
                                [-l {1,2,3,4,5,6,7,8}]
                                [--ipsum-max-age MINUTES] [--no-ok]
                                [--no-blocked] [--top-n NUMBER] [--json]
                                [--threads THREADS] [--version]
                                input_file [input_file ...]

Scan text / log file(s) for lines containing IPv4 addressess and optional
additional search terms, then check if the IP address would be blocked by
the IPsum block list (https://github.com/stamparm/ipsum). Print a report of
the findings.

positional arguments:
  input_file            Input file(s) to parse

optional arguments:
  -h, --help            show this help message and exit
  --encoding ENCODING   Encoding of input file(s) (default: utf-8)
  -L NUMBER, --older-logs-up-to-n NUMBER
                        If text file has '.log' as extension (case
                        insensitive), also look for older (possibly
                        compressed) log files like <file>.1, <file>.2.lzma,
                        <file>.3.gz, ..., <file>.<THIS_NUMBER>.bz2 etc.; use
                        0 to disable this behaviour (default: 0)
  --process-by-mtime    process multiple files sorted by their mtime
                        ascending (default: False)
  -s TERM, --include-term-case-insensitive TERM
                        beside an IP address, this search term must be
                        present in the log lines - can be given multiple
                        times, in which case all terms must be present
                        (default: None)
  -S TERM, --include-term-case-sensitive TERM
                        same as --include-term-case-insensitive, but case
                        sensitive (default: None)
  -x TERM, --exclude-term-case-insensitive TERM
                        exclude log lines containing this term - can be
                        given multiple times, in which case the appearance
                        of any of the terms will result in exclusion
                        (default: None)
  -X TERM, --exclude-term-case-sensitive TERM
                        Same as --exclude-term-case-insensitive, but case
                        sensitive (default: None)
  -n N_TH_IP, --n-th-ip N_TH_IP
                        use N-th IPv4 address appearing in line; can be
                        negative to count backwards from the end (-1 would
                        be the last IP) (default: 1)
  -l {1,2,3,4,5,6,7,8}, --ipsum-level {1,2,3,4,5,6,7,8}
                        IPsum level, lower means more IPs blocked (=IPs
                        appearing on this many blocklists suffice to block
                        the IP) (default: 3)
  --ipsum-max-age MINUTES
                        Use cached ipsum block list if existing and not
                        older than this many minutes, otherwise download a
                        new one; use 0 to always download (default: 60)
  --no-ok               omit printing non-blocked entries (default: False)
  --no-blocked          omit printing blocked entries (default: False)
  --top-n NUMBER        Print this many top matches in results; use 0 to
                        omit (default: 5)
  --json                Output result in JSON format to stdout (default:
                        False)
  --threads THREADS     process multiple files in parallel using this many
                        threads; often this is not faster; 1 means no
                        multithreading; use 'auto' to use a reasonable
                        number of threads (EXPERIMENTAL) (default: 1)
  --version             Print version number and exit (default: False)

Example: ipsum_log_block_check.py -S Nigeria -s "prince" -x test --n-th-ip 2
--top-n 10 --ipsum-level 2 /var/log/the_app.log
```

## License

GPL v3

## Author

Christoph Haunschmidt
