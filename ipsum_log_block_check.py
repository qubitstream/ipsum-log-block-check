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
import json
import lzma
import os
import platform
import re
import socket
import sys
import tempfile
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Queue
from threading import Thread
from types import ModuleType
from typing import Any, Iterable, Iterator, NamedTuple, Optional, Union

__version__ = "0.1.1"


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

TAB_REGEX = re.compile(r"\t+")

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


def detect_text_file_paths(
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


def text_to_ip_set(text: str) -> set[str]:
    """Extract IP addresses from text, line by line

    Args:
        text (str): text string with lines of IPs

    Raises:
        ValueError: Invalid IP address
        ValueError: File could not be read

    Returns:
        set[str]: a set of IP4 addresses as strings
    """
    blocked_ips: set[str] = set()
    try:
        for line_nr, line in enumerate(text.split(), start=1):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("#") and IP4_REGEX.fullmatch(line):
                blocked_ips.add(line)
            else:
                raise ValueError(
                    f"IPsum block list contains invalid IP address at line #{line_nr}: {line}"
                )
        return blocked_ips
    except Exception as e:
        raise ValueError(f"Failed to parse block list: {e}")


def get_ipsum_blocklist(
    level: int = 1, cached_max_age: timedelta = timedelta(minutes=60)
) -> tuple[set[str], datetime | None, Path | None]:
    """Download or read cached IPsum block list set

    Args:
        level (int, optional): IPsum level. Defaults to 1.
        cached_max_age (timedelta, optional): max age of cache
            Defaults to timedelta(minutes=60).

    Returns:
        tuple[str, datetime | None, Path | None]: Returns a tuple:
            - set with IPs from the IPsum block list
            - datetime of the IPsum data (cache file or download)
            - path to the IPsum cache file (if used)
    """
    tempdir_path = Path(tempfile.gettempdir())
    cache_file_path = (
        tempdir_path
        / f"ipsum_log_block_check__{getpass.getuser()}"
        / f"ipsum_blocked_ips__level_{level}.txt"
    )

    content_datetime: datetime | None = None
    needs_download = False
    content = ""

    if cache_file_path.is_file() and not is_file_older_than(
        file_path=cache_file_path, delta=cached_max_age
    ):
        try:
            content = cache_file_path.read_text(encoding="utf-8")
            content_datetime = datetime.fromtimestamp(
                cache_file_path.stat().st_mtime, tz=timezone.utc
            )
        except Exception as e:
            needs_download = True
            print(
                f"Failed to read cache file {cache_file_path}: {e}",
                file=sys.stderr,
            )
    else:
        needs_download = True

    if needs_download:
        content = download_textfile(IPSET_URL_FORMAT_STR.format(level=level))
        content_datetime = datetime.now(timezone.utc)

        # Try to save list to cache file
        try:
            if not cache_file_path.parent.is_dir():
                cache_file_path.parent.mkdir(parents=True)
            cache_file_path.write_text(content, encoding="utf-8")
        except OSError:
            # Not a deal-breaker, we just use the downloaded list in memory
            print(
                f"Failed to write cache file to {cache_file_path}",
                file=sys.stderr,
            )
            cache_file_path = None

    ip_set = text_to_ip_set(content)
    return ip_set, content_datetime, cache_file_path


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


def build_search_terms(
    include_term_case_insensitive: Iterable[str] | None,
    include_term_case_sensitive: Iterable[str] | None,
    exclude_term_case_insensitive: Iterable[str] | None,
    exclude_term_case_sensitive: Iterable[str] | None,
) -> set[SearchTerm]:
    search_terms: set[SearchTerm] = set()
    terms_data = (
        (include_term_case_insensitive, SearchTermKind.INCLUDE, False),
        (include_term_case_sensitive, SearchTermKind.INCLUDE, True),
        (exclude_term_case_insensitive, SearchTermKind.EXCLUDE, False),
        (exclude_term_case_sensitive, SearchTermKind.EXCLUDE, True),
    )
    for terms, kind, case_sensitive in terms_data:
        for term in terms or []:
            search_terms.add(
                SearchTerm(term=term, kind=kind, case_sensitive=case_sensitive)
            )
    return search_terms


def do_search(
    text_file_paths: Iterable[Path],
    search_terms: Optional[Iterable[SearchTerm]],
    n_th_ip: int = 1,
    encoding: str = "utf-8",
    max_workers: int | None = 1,
) -> Iterator[IPMatch]:
    search_terms_set: set[SearchTerm] = set(search_terms or [])
    input_paths: list[Path] = list(text_file_paths)

    if max_workers is None:
        max_workers = (os.cpu_count() or 1) + 4
    max_workers = min(len(input_paths), 32, max_workers)

    if max_workers <= 1 or len(input_paths) <= 1:
        for path in input_paths:
            yield from get_ip_matches(
                lines=get_lines(path, encoding),
                search_terms=search_terms_set,
                n_th_ip=n_th_ip,
            )
        return

    task_queue: "Queue[Optional[Path]]" = Queue()
    result_queue: "Queue[Union[IPMatch, object]]" = Queue()
    sentinel: object = object()

    # fill task queue with paths, then add sentinels
    for path in input_paths:
        task_queue.put(path)
    for _ in range(max_workers):
        task_queue.put(None)

    def worker() -> None:
        while True:
            path = task_queue.get()
            if path is None:
                break
            for match in get_ip_matches(
                lines=get_lines(path, encoding),
                search_terms=search_terms_set,
                n_th_ip=n_th_ip,
            ):
                result_queue.put(match)
        result_queue.put(sentinel)

    for _ in range(max_workers):
        Thread(target=worker, daemon=True).start()

    finished = 0
    while finished < max_workers:
        item = result_queue.get()
        if item is sentinel:
            finished += 1
        else:
            yield item  # type: ignore[union-attr]  # item is IPMatch


class BlockListSearch:
    def __init__(
        self,
        input_file: Path | Iterable[Path],
        encoding: str = "utf-8",
        older_logs_up_to_n: int = 0,
        process_by_mtime: bool = False,
        include_term_case_insensitive: Iterable[str] | None = None,
        include_term_case_sensitive: Iterable[str] | None = None,
        exclude_term_case_insensitive: Iterable[str] | None = None,
        exclude_term_case_sensitive: Iterable[str] | None = None,
        n_th_ip: int = 1,
        ipsum_level: int = 1,
        ipsum_max_age: int = 60,
        no_ok: bool = False,
        no_blocked: bool = False,
        top_n: int = 5,
    ):
        # Input files
        self.input_file = input_file
        self.encoding = encoding
        self.older_logs_up_to_n = older_logs_up_to_n
        self.process_by_mtime = process_by_mtime

        self.input_paths: list[Path] = []

        # Search stuff
        self.include_term_case_insensitive = include_term_case_insensitive or []
        self.include_term_case_sensitive = include_term_case_sensitive or []
        self.exclude_term_case_insensitive = exclude_term_case_insensitive or []
        self.exclude_term_case_sensitive = exclude_term_case_sensitive or []
        self.n_th_ip = n_th_ip

        self.search_terms: set[SearchTerm] = set()

        # Blocklist
        self.ipsum_level = ipsum_level
        self.ipsum_max_age_minutes = ipsum_max_age

        self.ipsum_datetime: datetime | None = None
        self.ipsum_cache_file: Path | None = None

        # Output control
        self.no_ok = no_ok
        self.no_blocked = no_blocked
        self.top_n = top_n

        self.blacklisted_ips: set[str] = set()
        self.all_ips: list[str] = []
        self.blocked_ips: list[str] = []
        self.unblocked_ips: list[str] = []
        self.run_at: datetime | None = None

    def get_blacklisted_ips(self) -> set[str]:
        ip_set, self.ipsum_datetime, self.ipsum_cache_file = get_ipsum_blocklist(
            level=self.ipsum_level,
            cached_max_age=timedelta(minutes=self.ipsum_max_age_minutes),
        )
        return ip_set

    def parse(self, threads: int | None = 1) -> None:
        try:
            self.blacklisted_ips = self.get_blacklisted_ips()
        except Exception as e:
            print(
                f"Failed to parse block list: {e}",
                file=sys.stderr,
            )
            sys.exit(1)

        self.input_paths = detect_text_file_paths(
            text_file_path=self.input_file,
            older_logs_upto_n=self.older_logs_up_to_n,
            sort_by_mtime=self.process_by_mtime,
        )
        if not self.input_paths:
            print("No suitable input files found", file=sys.stderr)
            sys.exit(1)

        self.search_terms = build_search_terms(
            include_term_case_insensitive=self.include_term_case_insensitive,
            include_term_case_sensitive=self.include_term_case_sensitive,
            exclude_term_case_insensitive=self.exclude_term_case_insensitive,
            exclude_term_case_sensitive=self.exclude_term_case_sensitive,
        )

        self.all_ips = []
        self.blocked_ips = []
        self.unblocked_ips = []

        self.run_at = datetime.now(timezone.utc)

        ip_matches = do_search(
            text_file_paths=self.input_paths,
            search_terms=self.search_terms,
            n_th_ip=self.n_th_ip,
            encoding=self.encoding,
            max_workers=threads,
        )

        self.process_matches(ip_matches)

    def process_matches(self, ip_matches: Iterator[IPMatch]) -> None:
        """Process single IPMatch object"""
        output_string_min_length = 28
        try:
            terminal_width = os.get_terminal_size().columns
        except OSError:
            terminal_width = None
        width_available = (
            (terminal_width - output_string_min_length - 1) if terminal_width else None
        )

        for ip_match in ip_matches:
            self.all_ips.append(ip_match.ip)

            is_blocked = ip_match.ip in self.blacklisted_ips
            if is_blocked:
                self.blocked_ips.append(ip_match.ip)
            else:
                self.unblocked_ips.append(ip_match.ip)

            omit_print = (is_blocked and self.no_blocked) or (
                not is_blocked and self.no_ok
            )
            if not omit_print:
                print(
                    "{0:>7} | {1:<15} | {2}".format(
                        "BLOCKED" if is_blocked else "OK",
                        ip_match.ip,
                        fit_line_with_ellipsis(
                            line=TAB_REGEX.sub(" ", ip_match.line),
                            max_width=width_available,
                        ),
                    )
                )

    @staticmethod
    def process_to_json_compatible(obj: Any) -> Any:
        if isinstance(obj, (str, int, float, bool, list, dict, type(None))):
            return obj
        if isinstance(obj, timedelta):
            return obj.total_seconds()
        if isinstance(obj, datetime):
            return obj.astimezone().isoformat()
        elif isinstance(obj, Path):
            return str(obj.resolve())
        elif isinstance(obj, set):
            return sorted(obj)
        elif isinstance(obj, SearchTerm):
            return obj._asdict()
        elif isinstance(obj, SearchTermKind):
            return obj.value
        elif isinstance(obj, tuple):
            return list(obj)
        else:
            return str(obj)

    def get_result_as_dict(self) -> dict[str, Any]:
        unique_ips = set(self.all_ips)
        unique_blocked_ips = set(self.blocked_ips)
        unique_unblocked_ips = set(self.unblocked_ips)
        data = {
            "params": {
                "input_file": self.input_file,
                "older_logs_up_to_n": self.older_logs_up_to_n,
                "process_by_mtime": self.process_by_mtime,
                "include_term_case_insensitive": self.include_term_case_insensitive,
                "include_term_case_sensitive": self.include_term_case_sensitive,
                "exclude_term_case_insensitive": self.exclude_term_case_insensitive,
                "exclude_term_case_sensitive": self.exclude_term_case_sensitive,
                "n_th_ip": self.n_th_ip,
                "ipsum_level": self.ipsum_level,
                "ipsum_max_age_minutes": self.ipsum_max_age_minutes,
                "no_ok": self.no_ok,
                "no_blocked": self.no_blocked,
                "top_n": self.top_n,
            },
            "processed": {
                "hostname": socket.gethostname(),
                "user": getpass.getuser(),
                "platform": platform.platform(),
                "run_at": self.run_at if self.run_at else None,
                "input_paths": self.input_paths,
                "search_terms": self.search_terms,
                "blacklisted_ips": self.blacklisted_ips,
                "blacklisted_count": len(self.blacklisted_ips),
                "ipsum_datetime": self.ipsum_datetime,
                "ipsum_cache_file": self.ipsum_cache_file,
            },
            "results": {
                "entries": {
                    "total": self.all_ips,
                    "total_count": len(self.all_ips),
                    "blocked": self.blocked_ips,
                    "blocked_count": len(self.blocked_ips),
                    "unblocked": self.unblocked_ips,
                    "unblocked_count": len(self.unblocked_ips),
                    "blocked_ratio": (len(self.blocked_ips) / len(self.all_ips))
                    if self.all_ips
                    else None,
                },
                "ips": {
                    "total": unique_ips,
                    "total_count": len(unique_ips),
                    "blocked": unique_blocked_ips,
                    "blocked_count": len(unique_blocked_ips),
                    "unblocked": unique_unblocked_ips,
                    "unblocked_count": len(unique_unblocked_ips),
                    "blocked_ratio": (len(unique_blocked_ips) / len(unique_ips))
                    if unique_ips
                    else None,
                    "top": {
                        "n": self.top_n,
                        "total": [],
                        "blocked": [],
                        "unblocked": [],
                    },
                },
            },
        }

        if self.top_n > 0:
            for key, dataset in (
                ("total", self.all_ips),
                ("unblocked", self.unblocked_ips),
                ("blocked", self.blocked_ips),
            ):
                most_common = Counter(dataset).most_common(self.top_n)
                data["results"]["ips"]["top"][key] = [
                    {"ip": ip, "count": count} for ip, count in most_common
                ]

        return data

    def get_result_as_json(self, ensure_ascii=True, no_ips: bool = True) -> str:
        data = self.get_result_as_dict()

        # Remove potentially massive IP lists
        if no_ips:
            data["processed"]["blacklisted_ips"] = None
            for key in ["total", "blocked", "unblocked"]:
                data["results"]["entries"][key] = None
                data["results"]["ips"][key] = None
        data["processed"]["search_terms"] = [
            search_term._asdict() for search_term in data["processed"]["search_terms"]
        ]

        return json.dumps(
            data,
            indent=4,
            ensure_ascii=ensure_ascii,
            default=BlockListSearch.process_to_json_compatible,
        )

    def get_result_as_str(self) -> str:
        data = self.get_result_as_dict()

        # Alias variables for readability
        params = data["params"]
        processed = data["processed"]
        entries = data["results"]["entries"]
        ips = data["results"]["ips"]

        lines = [""]
        lines += [
            "__________ Params __________",
            f"IPsum list level {params['ipsum_level']} "
            f"(containing {processed['blacklisted_count']} IPs)",
            f"IPsum list cache file: {processed['ipsum_cache_file']}",
            f"IPsum list date: {processed['ipsum_datetime'].isoformat() if processed['ipsum_datetime'] else '-'}",
            f"Log file(s) parsed ({len(processed['input_paths'])}):",
        ]
        for i, input_file_path in enumerate(processed["input_paths"], start=1):
            lines.append(f"{i:>4}. {input_file_path.resolve()}")

        lines += [
            f"Looking at IP number {params['n_th_ip']} in each line",
            "Search term(s):",
        ]
        if processed["search_terms"]:
            for i, search_term in enumerate(processed["search_terms"], start=1):
                lines.append(
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
            lines.append("(no search terms given)")

        if ips["total_count"]:
            if params["top_n"] > 0:
                lines.append("")
                for key in ("total", "unblocked", "blocked"):
                    lines.append(
                        f"__________ Top {params['top_n']} {key} IPs __________"
                    )
                    most_common_ips = ips["top"][key]
                    if most_common_ips:
                        for place, most_common_data in enumerate(
                            most_common_ips, start=1
                        ):
                            lines.append(
                                f"{place:>2}. | {most_common_data['ip']:<15} | {most_common_data['count']}x"
                            )
                    else:
                        lines.append("(no IPs found)")
                lines.append("")

            lines += [
                "__________ Results __________",
                (
                    f"Using IPsum list level {params['ipsum_level']} "
                    f"({processed['blacklisted_count']} IPs):"
                ),
                (
                    f"  {entries['blocked_ratio'] * 100: >6.2f}% entries would be blocked "
                    f"({entries['blocked_count']} out of {entries['total_count']}, "
                    f"unblocked: {entries['unblocked_count']})"
                ),
                (
                    f"  {ips['blocked_ratio'] * 100: >6.2f}% unique IPs "
                    f"would be blocked "
                    f"({ips['blocked_count']} out of {ips['total_count']}, "
                    f"unblocked: {ips['unblocked_count']})"
                ),
            ]
        else:
            lines += [
                "",
                "__________ Results __________",
                (
                    "No entries with IPs or IP on position {ippos}{terms} found".format(
                        ippos=params["n_th_ip"],
                        terms=(
                            " and given search terms"
                            if processed["search_terms"]
                            else ""
                        ),
                    )
                ),
            ]

        return os.linesep.join(lines)


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
        default=0,
        metavar="NUMBER",
        help=(
            "If text file has '.log' as extension (case insensitive), also "
            "look for older (possibly compressed) log files like "
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
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result in JSON format to stdout",
    )
    parser.add_argument(
        "--threads",
        type=str,
        default="1",
        help=(
            "process multiple files in parallel using this many threads; "
            "often this is not faster; 1 means no multithreading; use "
            "'auto' to use a reasonable number of threads "
            "(EXPERIMENTAL)"
        ),
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version number and exit",
    )

    args = parser.parse_args()

    if args.version:
        print(__version__)
        sys.exit(0)

    for input_file in args.input_file:
        if not input_file.is_file():
            parser.error(f"Input file does not exist: {input_file}")

    if args.n_th_ip == 0:
        parser.error("--n-th-ip must not be 0")

    if args.ipsum_max_age < 0:
        parser.error("--ipsum-max-age must be positive or 0")

    if args.top_n < 0:
        parser.error("--top-n must not be negative")

    threads = 1
    if args.threads:
        if args.threads.lower() == "auto":
            threads = None
        else:
            try:
                threads = int(args.threads)
                if threads < 1:
                    raise ValueError
            except ValueError:
                parser.error("--threads must be an integer >= 1 or 'auto'")

    kwargs = vars(args)

    as_json = kwargs.pop("json")
    kwargs.pop("threads")
    kwargs.pop("version")
    if as_json:
        kwargs["no_ok"] = True
        kwargs["no_blocked"] = True
    block_list_search = BlockListSearch(**kwargs)

    block_list_search.parse(threads=threads)

    if as_json:
        print(block_list_search.get_result_as_json())
    else:
        print(block_list_search.get_result_as_str())


if __name__ == "__main__":
    main()
