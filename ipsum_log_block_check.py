#!/usr/bin/env python3
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
####################################################################################
#
# A Python script to evaluate IP addresses in a log file for blocking by IPsum
#
# tested on Python 3.7+
#
# Christoph Haunschmidt, started 2025-04
#
# /// script
# requires-python = ">=3.7"
# dependencies = []
# ///
"""Scan text / log file(s) for lines containing IPv4 addressess and
optional additional search terms, then check if the IP address
would be blocked by the IPsum block list (https://github.com/stamparm/ipsum).
Print a report of the findings.
"""

from __future__ import annotations

import argparse
import bz2
import enum
import getpass
import gzip
import lzma
import os
import re
import sys
import tempfile
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Iterable, Iterator, NamedTuple

# fmt: off
IP4_REGEX = re.compile(
    r"(?<!\d)"                                           # Negative lookbehind: no digit
    r"(?:"
        r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"  # First three octets: 0-255
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"           # Last octet: 0-255
    r")"
    r"(?!\d)"                                            # Negative lookahead: no digit 
)
# fmt: on

IPSET_URL_FORMAT_STR = "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/{level}.txt"


class SearchTermKind(enum.Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


SearchTerm = NamedTuple(
    "SearchTerm", [("term", str), ("kind", SearchTermKind), ("case_sensitive", bool)]
)


IPMatch = NamedTuple("IPMatch", [("ip", str), ("line", str)])

SUFFIXES_TO_MODULE: dict[tuple[str], ModuleType] = {
    (".bz2",): bz2,
    (".gz",): gzip,
    (".lzma",): lzma,
}

SUPPORTED_COMPRESSION_SUFFIXES: set[str] = set(
    suffix for suffixes in SUFFIXES_TO_MODULE.keys() for suffix in suffixes
)


def download_textfile(url: str, encoding: str = "utf-8") -> str:
    """Download text file and returns the content (as string)

    Args:
        url (str): Source URL
        encoding (str, optional): Encoding. Defaults to "utf-8".

    Returns:
        str: Text content of downloaded file
    """
    with urllib.request.urlopen(url) as response:
        text = response.read().decode(encoding)
    return text


def is_file_older_than(file_path: Path, delta: timedelta) -> bool:
    """Check if mod time of file is older than delta

    Args:
        file_path (Path): File to check
        delta (timedelta): Age to check for

    Returns:
        bool: True if file is older than delta
    """
    modified_time = datetime.fromtimestamp(file_path.stat().st_mtime)
    current_time = datetime.now()
    return (current_time - modified_time) > delta


def fit_line_with_ellipsis(
    line: str, max_width: int | None = None, ellipsis: str = " [...] "
) -> str:
    """Output line fitting into max_width chars

    If line is shorter than max_width, it is returned as is

    If line is longer than max_width, it is truncated to max_width chars and
    ellipsis is added in the middle

    Args:
        line (str): line to fit
        max_width (int, optional): Maximum width.
            Defaults to None (i.e. no limit).
        ellipsis (str, optional): Put into the middle of the line if shortened.
            Defaults to " [...] ".

    Returns:
        str: (the potentially shortened) line
    """
    if max_width is None:
        return line

    ellipsis_length = len(ellipsis)

    if len(line) <= max_width:
        return line

    if max_width <= ellipsis_length:
        return ellipsis.strip()

    remaining_space = max_width - ellipsis_length
    start_part_length = remaining_space // 2
    end_part_length = remaining_space - start_part_length

    start_part = line[:start_part_length]
    end_part = line[-end_part_length:]

    return f"{start_part}{ellipsis}{end_part}"


def get_lines(text_file_path: Path, encoding: str = "utf-8") -> Iterator[str]:
    """Yield lines from text file

    Args:
        text_file_path (Path): Text file (or *.bz2 or *.gz file)
        encoding (str, optional): Encoding. Defaults to "utf-8".

    Yields:
        Iterator[str]: Iterator of lines
    """
    module: ModuleType | None = None
    lower_suffix = text_file_path.suffix.lower()
    for suffixes, module_for_suffixes in SUFFIXES_TO_MODULE.items():
        if lower_suffix in suffixes:
            module = module_for_suffixes
            break
    try:
        if module is not None:
            with module.open(text_file_path, "rt", encoding=encoding) as f:
                for line in f:
                    yield line.strip()
        else:
            with open(text_file_path, "r", encoding=encoding) as f:
                for line in f:
                    yield line.strip()
    except Exception as e:
        print(f"Failed to read {text_file_path}: {e}", file=sys.stderr)


def get_text_file_paths(
    text_file_path: Path | Iterable[Path],
    older_logs_upto_n: int | None = None,
    sort_by_mtime: bool = True,
) -> list[Path]:
    """Get all text file paths

    Args:
        text_file_path (Path | Iterable[Path]): Paths or paths to text file
        older_logs_upto_n (int, optional): If a file is a *.log file, also
            look for <file>.1 for <file>.2.gz etc. Defaults to None.
        sort_by_mtime (bool, optional): Sort result paths by modification time
            ascending. Defaults to True.

    Returns:
        list[Path]: Paths to process
    """
    if not isinstance(text_file_path, Iterable):
        text_file_path = [text_file_path]

    result_paths: list[Path] = []

    for text_file_path in text_file_path:
        # Look for older log files (compressed or not)
        if (
            text_file_path.suffix.lower() == ".log"
            and older_logs_upto_n is not None
            and older_logs_upto_n > 0
        ):
            for n in range(older_logs_upto_n, 0, -1):
                older_log_path = Path(f"{text_file_path}.{n}")
                if not older_log_path.is_file():
                    for suffix in SUPPORTED_COMPRESSION_SUFFIXES:
                        older_log_path_compressed = Path(f"{older_log_path}{suffix}")
                        if older_log_path_compressed.is_file():
                            older_log_path = older_log_path_compressed
                            break
                if older_log_path.is_file() and older_log_path not in result_paths:
                    result_paths.append(older_log_path)

        if text_file_path.is_file() and text_file_path not in result_paths:
            result_paths.append(text_file_path)

    if sort_by_mtime:
        result_paths = sorted(result_paths, key=lambda p: p.stat().st_mtime)

    return result_paths


def get_ip_matches(
    lines: Iterator[str],
    search_terms: Iterable[SearchTerm] | None,
    n_th_ip: int = 1,
) -> Iterator[IPMatch]:
    """Yield IP matches of given lines

    Args:
        lines (Iterator[str]): Lines
        search_terms (Iterable[SearchTerm] | None): Search terms to look for.
            If None, no search is performed
        n_th_ip (int, optional): Use N-th IPv4 address appearing in line.
            Can be negative to count backwards from the end (-1 is the last IP)
            If N-th IP is not found, the line is excluded.
            Defaults to 1.

    Yields:
        Iterator[IPMatch]: Iterator of IPMatch named tuples
    """
    if n_th_ip == 0:
        raise ValueError("n_th_ip must not be 0")

    n_th_ip_abs = abs(n_th_ip)

    # Pre-convert all case-insensitive terms to lower case
    has_case_sensitive_search_terms = False
    effective_search_terms: list[SearchTerm] = []
    for search_term in set(search_terms or []):
        if search_term.case_sensitive:
            effective_search_terms.append(search_term)
            has_case_sensitive_search_terms = True
        else:
            effective_search_terms.append(
                SearchTerm(
                    term=search_term.term.lower(),
                    kind=search_term.kind,
                    case_sensitive=False,
                )
            )

    for line in lines:
        ips_found: list[str] = IP4_REGEX.findall(line)

        # skip line if no IP found at index
        if len(ips_found) < n_th_ip_abs:
            continue

        # Avoid conversion to lower case if not needed
        line_lower = line if has_case_sensitive_search_terms else line.lower()

        terms_ok = True

        for search_term in effective_search_terms:
            if search_term.kind == SearchTermKind.EXCLUDE:
                if search_term.term in (
                    line if search_term.case_sensitive else line_lower
                ):
                    terms_ok = False
                    break
            elif search_term.kind == SearchTermKind.INCLUDE:
                if search_term.term not in (
                    line if search_term.case_sensitive else line_lower
                ):
                    terms_ok = False
                    break

        if terms_ok:
            ip_index = (n_th_ip - 1) if n_th_ip > 0 else n_th_ip
            yield IPMatch(ip=ips_found[ip_index], line=line)


def do_search(
    text_file_paths: Path | Iterable[Path],
    search_terms: Iterable[SearchTerm] | None,
    n_th_ip: int = 1,
    encoding: str = "utf-8",
) -> Iterator[IPMatch]:
    search_terms = set(search_terms or [])

    if not isinstance(text_file_paths, Iterable):
        text_file_paths = [text_file_paths]

    for text_file_path in text_file_paths:
        for ip_match in get_ip_matches(
            lines=get_lines(text_file_path=text_file_path, encoding=encoding),
            search_terms=search_terms,
            n_th_ip=n_th_ip,
        ):
            yield ip_match


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog='Example: ipsum_log_block_check.py -S Nigeria -s "prince" -x test --n-th-ip 2 --top-n 10 --ipsum-level 2 /var/log/the_app.log',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Input file and processing
    parser.add_argument(
        "input_file", type=Path, nargs="+", help="Input file(s) to parse"
    )
    parser.add_argument(
        "--encoding",
        type=str,
        default="utf-8",
        help="Encoding of input file(s)",
    )
    parser.add_argument(
        "-L",
        "--older-logs-up-to-n",
        type=int,
        default=1,
        metavar="NUMBER",
        help=(
            "If text file has '.log' as extension (case insensitive), also "
            "look for older (possibly comressed) log files like "
            "<file>.1, <file>.2.lzma, "
            "<file>.3.gz, ...,  <file>.<THIS_NUMBER>.bz2 etc.; use 0 to "
            "disable this behaviour"
        ),
    )
    parser.add_argument(
        "--process-by-mtime",
        action="store_true",
        help="process multiple files sorted by their mtime ascending",
    )

    # Search
    parser.add_argument(
        "-s",
        "--include-term-case-insensitive",
        type=str,
        metavar="TERM",
        action="append",
        help=(
            "beside an IP address, this search term must be present in the "
            "log lines - can be given multiple times, in which case "
            "all terms must be present"
        ),
    )
    parser.add_argument(
        "-S",
        "--include-term-case-sensitive",
        type=str,
        metavar="TERM",
        action="append",
        help=("same as --include-term-case-insensitive, but case sensitive"),
    )
    parser.add_argument(
        "-x",
        "--exclude-term-case-insensitive",
        type=str,
        metavar="TERM",
        action="append",
        help=(
            "exclude log lines containing this term - "
            "can be given multiple times, in which case the appearance of any "
            "of the terms will result in exclusion"
        ),
    )
    parser.add_argument(
        "-X",
        "--exclude-term-case-sensitive",
        type=str,
        metavar="TERM",
        action="append",
        help=("Same as --exclude-term-case-insensitive, but case sensitive"),
    )
    parser.add_argument(
        "-n",
        "--n-th-ip",
        type=int,
        default=1,
        help=(
            "use N-th IPv4 address appearing in line; "
            "can be negative to count backwards from the end "
            "(-1 would be the last IP)"
        ),
    )

    # IPsum options
    parser.add_argument(
        "-l",
        "--ipsum-level",
        type=int,
        choices=[1, 2, 3, 4, 5, 6, 7, 8],
        default=3,
        help="IPsum level, lower means more IPs blocked (=IPs appearing on "
        "this many blocklists suffice to block the IP)",
    )
    parser.add_argument(
        "--ipsum-max-age",
        type=int,
        default=60,
        metavar="MINUTES",
        help="Use cached ipsum block list if existing and not older than this "
        "many minutes, otherwise download a new one; use 0 to always download ",
    )

    # Output
    parser.add_argument(
        "--no-ok",
        action="store_true",
        help="omit printing non-blocked entries",
    )
    parser.add_argument(
        "--no-blocked",
        action="store_true",
        help="omit printing blocked entries",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=5,
        metavar="NUMBER",
        help=("Print this many top matches in results; use 0 to omit"),
    )

    args = parser.parse_args()

    if args.n_th_ip == 0:
        parser.error("--n-th-ip must not be 0")

    if args.ipsum_max_age < 0:
        parser.error("--ipsum-max-age must be positive or 0")

    if args.top_n < 0:
        parser.error("--top-n must not be negative")

    for input_file in args.input_file:
        if not input_file.is_file():
            parser.error(f"Input file does not exist: {input_file}")

    # First, download or update the block list
    tempdir_path = Path(tempfile.gettempdir())
    ipsum_block_file_path = (
        tempdir_path
        / "ipsum_log_block_check"
        / getpass.getuser()
        / f"ipsum_blocked_ips__level_{args.ipsum_level}.txt"
    )
    ipsum_datetime: datetime | None = None

    try:
        if not ipsum_block_file_path.is_file() or is_file_older_than(
            file_path=ipsum_block_file_path, delta=timedelta(minutes=args.ipsum_max_age)
        ):
            ipsum_blocked_ips_text = download_textfile(
                IPSET_URL_FORMAT_STR.format(level=args.ipsum_level)
            )
            ipsum_datetime = datetime.now()
            try:
                if not ipsum_block_file_path.parent.is_dir():
                    ipsum_block_file_path.parent.mkdir(parents=True)
                ipsum_block_file_path.write_text(
                    ipsum_blocked_ips_text, encoding="utf-8"
                )
            except OSError:
                print(
                    f"Failed to write cache file to {ipsum_block_file_path}",
                    file=sys.stderr,
                )
        else:
            ipsum_blocked_ips_text = ipsum_block_file_path.read_text(encoding="utf-8")
            ipsum_datetime = datetime.fromtimestamp(
                ipsum_block_file_path.stat().st_mtime
            )

        ipsum_blocked_ips = set(ipsum_blocked_ips_text.split())
    except Exception as e:
        print(f"Failed to get IPsum block list: {e}", file=sys.stderr)
        sys.exit(1)

    text_file_paths = get_text_file_paths(
        args.input_file,
        older_logs_upto_n=args.older_logs_up_to_n,
        sort_by_mtime=args.process_by_mtime,
    )

    # Build search terms
    search_terms: set[SearchTerm] = set()
    terms_data = (
        (args.include_term_case_insensitive, SearchTermKind.INCLUDE, False),
        (args.include_term_case_sensitive, SearchTermKind.INCLUDE, True),
        (args.exclude_term_case_insensitive, SearchTermKind.EXCLUDE, False),
        (args.exclude_term_case_sensitive, SearchTermKind.EXCLUDE, True),
    )
    for terms, kind, case_sensitive in terms_data:
        for term in terms or []:
            search_terms.add(
                SearchTerm(term=term, kind=kind, case_sensitive=case_sensitive)
            )

    # Get matches
    ip_matches = do_search(
        text_file_paths=text_file_paths,
        search_terms=search_terms,
        n_th_ip=args.n_th_ip,
        encoding=args.encoding,
    )

    # Print matches
    output_string_min_length = 28
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = None
    width_available = (
        (terminal_width - output_string_min_length - 1) if terminal_width else None
    )

    all_ips: list[str] = []
    blocked_ips: list[str] = []
    unblocked_ips: list[str] = []
    for ip_match in ip_matches:
        all_ips.append(ip_match.ip)

        is_blocked = ip_match.ip in ipsum_blocked_ips
        if is_blocked:
            blocked_ips.append(ip_match.ip)
        else:
            unblocked_ips.append(ip_match.ip)

        omit_print = (is_blocked and args.no_blocked) or (not is_blocked and args.no_ok)
        if not omit_print:
            print(
                "{0:>7} | {1:<15} | {2}".format(
                    "BLOCKED" if is_blocked else "OK",
                    ip_match.ip,
                    fit_line_with_ellipsis(ip_match.line, max_width=width_available),
                )
            )

    # Output used parameters and results
    blocked_count = len(blocked_ips)
    unique_blocked_count = len(set(blocked_ips))
    unblocked_count = len(unblocked_ips)
    unique_unblocked_count = len(set(unblocked_ips))
    all_count = len(all_ips)
    all_unique_count = len(set(all_ips))

    print()
    print("__________ Params __________")
    print(
        f"IPsum list level {args.ipsum_level} (containing {len(ipsum_blocked_ips)} IPs)"
    )
    print(f"IPsum list cache file: {ipsum_block_file_path}")
    print(f"IPsum list date: {ipsum_datetime.isoformat() if ipsum_datetime else '-'}")

    print("Log file(s) parsed:")
    for i, text_file_path in enumerate(text_file_paths, start=1):
        print(f"{i:>4}. {text_file_path.resolve()}")

    print(f"Looking at IP at position {args.n_th_ip} in each line")

    print("Search term(s):")
    if search_terms:
        for i, search_term in enumerate(search_terms, start=1):
            print(
                "{0:>4}. {1} {2:>16}: {3}".format(
                    i,
                    "+" if search_term.kind == SearchTermKind.INCLUDE else "-",
                    "case sensitive"
                    if search_term.case_sensitive
                    else "case insensitive",
                    search_term.term,
                )
            )
    else:
        print("(no search terms given)")

    if all_unique_count:
        if args.top_n > 0:
            print()
            print(f"__________ Top {args.top_n} total IPs __________")
            for place, (ip, count) in enumerate(
                Counter(all_ips).most_common(args.top_n), start=1
            ):
                print(f"{place:>2}. | {ip:<15} | {count}x")

            print(f"__________ Top {args.top_n} unblocked IPs __________")
            for place, (ip, count) in enumerate(
                Counter(unblocked_ips).most_common(args.top_n), start=1
            ):
                print(f"{place:>2}. | {ip:<15} | {count}x")

            print(f"__________ Top {args.top_n} blocked IPs __________")
            for place, (ip, count) in enumerate(
                Counter(blocked_ips).most_common(args.top_n), start=1
            ):
                print(f"{place:>2}. | {ip:<15} | {count}x")
            print()

        print("__________ Results __________")
        print(
            f"Using IPsum list level {args.ipsum_level} ({len(ipsum_blocked_ips)} IPs):"
        )
        print(
            f"{blocked_count / all_count: >7.2%} entries would be blocked "
            f"({blocked_count} out of {all_count}, "
            f"unblocked: {unblocked_count})"
        )
        print(
            f"{unique_blocked_count / all_unique_count: >7.2%} unique IPs "
            f"would be blocked "
            f"({unique_blocked_count} out of {all_unique_count}, "
            f"unblocked: {unique_unblocked_count})"
        )
    else:
        print()
        print("__________ Results __________")
        print(
            "No entries with IPs or IP on position {ippos}{terms} found".format(
                ippos=args.n_th_ip,
                terms=(" and given search terms" if search_terms else ""),
            )
        )


if __name__ == "__main__":
    main()
