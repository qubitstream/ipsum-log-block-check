IPsum Log Block Check
=====================

A Python script to scan log files for IPv4 addresses and determine whether they appear on the [IPsum block list](https://github.com/stamparm/ipsum).

Useful for analyzing access logs or security event logs to identify potentially malicious IP addresses and evaluate how the IPsum blocklist at the given level would block those
(by using for example [ufw-blocklist](https://github.com/poddmo/ufw-blocklist))

## Features

- Parses plain text or compressed log files (`.gz`, `.bz2`, `.lzma`)
- Extracts IPv4 addresses from log lines
- Filters log entries by include/exclude search terms (case sensitive or insensitive)
- Selects the N-th IPv4 address from each line for evaluation
  (supports negative indexing)
- Checks IPs against different levels of the IPsum block list
- Supports caching of IPsum data (with optional expiration)
- Outputs a summary and top N matched IPs
- Handles log rotation: supports automatically parsing older `.log.N(.gz|.bz2|.lzma)` files
- Memory-efficient: processes data line per line

## Requirements

- Python 3.7+, so all supported versions can run this
- No third-party dependencies!

## Installation

Clone the repo:

```shell
git clone https://github.com/qubitstream/ipsum-log-block-check.git
cd ipsum-log-block-check
```

## Example

### Simple example

```shell
python ipsum_log_block_check.py /var/log/nginx/access.log -S POST --ipsum-level 2
```

Output (redacted):

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

### Complex example

```shell
python ipsum_log_block_check.py \
  -S "Failed password" \
  -x "internal" \
  --n-th-ip -1 \
  --ipsum-level 1 \
  --top-n 10 \
  --older-logs-up-to-n 3 \
  /var/log/auth.log
```

## Output

Each matched line is labeled as BLOCKED or OK and includes the relevant IP and a snippet of the log line. A summary is printed at the end, including:

- Total and unique blocked/unblocked IPs
- IPsum level and cache file info
- Parsed log files
- Top N matched IPs (total/blocked/unblocked)

## Help / Usage

The output of

```shell
python ipsum_log_block_check.py --help
```

shows

```
usage: ipsum_log_block_check.py [-h] [--encoding ENCODING] [-L NUMBER]
                                [--process-by-mtime] [-s TERM] [-S TERM]
                                [-x TERM] [-X TERM] [-n N_TH_IP]
                                [-l {1,2,3,4,5,6,7,8}]
                                [--ipsum-max-age MINUTES] [--no-ok]
                                [--no-blocked] [--top-n NUMBER]
                                input_file [input_file ...]

Scan text / log file(s) for lines containing IPv4 addressess and optional
additional search terms, then check if the IP address would be blocked by the
IPsum block list (https://github.com/stamparm/ipsum). Print a report of the
findings.

positional arguments:
  input_file            Input file(s) to parse

options:
  -h, --help            show this help message and exit
  --encoding ENCODING   Encoding of input file(s) (default: utf-8)
  -L, --older-logs-up-to-n NUMBER
                        If text file has '.log' as extension (case
                        insensitive), also look for older (possibly
                        comressed) log files like <file>.1, <file>.2.lzma,
                        <file>.3.gz, ..., <file>.<THIS_NUMBER>.bz2 etc.; use
                        0 to disable this behaviour (default: 1)
  --process-by-mtime    process multiple files sorted by their mtime
                        ascending (default: False)
  -s, --include-term-case-insensitive TERM
                        beside an IP address, this search term must be
                        present in the log lines - can be given multiple
                        times, in which case all terms must be present
                        (default: None)
  -S, --include-term-case-sensitive TERM
                        same as --include-term-case-insensitive, but case
                        sensitive (default: None)
  -x, --exclude-term-case-insensitive TERM
                        exclude log lines containing this term - can be given
                        multiple times, in which case the appearance of any
                        of the terms will result in exclusion (default: None)
  -X, --exclude-term-case-sensitive TERM
                        Same as --exclude-term-case-insensitive, but case
                        sensitive (default: None)
  -n, --n-th-ip N_TH_IP
                        use N-th IPv4 address appearing in line; can be
                        negative to count backwards from the end (-1 would be
                        the last IP) (default: 1)
  -l, --ipsum-level {1,2,3,4,5,6,7,8}
                        IPsum level, lower means more IPs blocked (=IPs
                        appearing on this many blocklists suffice to block
                        the IP) (default: 3)
  --ipsum-max-age MINUTES
                        Use cached ipsum block list if existing and not older
                        than this many minutes, otherwise download a new one;
                        use 0 to always download (default: 60)
  --no-ok               omit printing non-blocked entries (default: False)
  --no-blocked          omit printing blocked entries (default: False)
  --top-n NUMBER        Print this many top matches in results; use 0 to omit
                        (default: 5)

Example: ipsum_log_block_check.py -S Nigeria -s "prince" -x test --n-th-ip 2
--top-n 10 --ipsum-level 2 /var/log/the_app.log
```

## Author

Christoph Haunschmidt
