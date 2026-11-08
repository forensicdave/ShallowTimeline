#!/usr/bin/env python3
"""
ShallowTimeline - poor man's timeline from `ls -alR` or Windows `dir /s` output.

Parses recursive long listings (GNU coreutils, BSD/macOS, busybox, and the
Windows cmd.exe `dir /s` command) and emits one record per file as CSV or
JSONL: time, size, filename (plus optional extra fields), sorted
chronologically. It can also write a Sleuth Kit bodyfile (-f bodyfile) for
mactime, plaso or Timesketch.

Supported timestamp styles:
  default        Oct 30 13:17   /  Oct 30  2024       (month-day)
                 30 Oct 13:17   /  30 Oct  2024       (day-month locales)
  macOS -T       Oct 30 13:17:05 2024
  long-iso       2024-10-30 13:17
  full-iso       2024-10-30 13:17:05.123456789 +0000   (ls --full-time)
  iso            10-30 13:17    /  2024-10-30

Notes for analysts:
  * The time shown is whatever ls displayed: mtime by default, ctime with -c,
    atime with -u. Use --time-label to record which.
  * Default-style listings omit the year for recent files (< ~6 months old).
    The year is inferred relative to --ref-date, which should be the date
    the listing was captured. If omitted, today's date is used.
  * Default-style listings only give minute (recent) or day (old) precision.
    The 'precision' field (with --extended) records this.
  * Times are local to the system that ran ls unless full-iso was used.
  * If the source clock was wrong, --skew moves every timestamp by the
    measured offset. Entries dated after --ref-date are reported.

Windows `dir /s` notes:
  * Dates follow the system locale (MM/DD/YYYY, DD/MM/YYYY, YYYY-MM-DD).
    The order is detected from the data when a day > 12 appears; otherwise
    use --date-order. Precision is always minute; /t:c and /t:a switch the
    listed time to creation/access time.
  * The counts are checked against dir's own "Total Files Listed" summary.
  * dir silently skips directories it cannot open (no error is printed), so
    any <DIR> entry with no "Directory of" section of its own is reported as
    not read - usually access denied. Use --skipped-dirs to save the list.

  * dir /s follows directory symlinks that resolve locally (C:\\Users\\All Users
    -> C:\\ProgramData), so their contents appear twice. --drop-followed-links
    drops the copy reached through the link when its target is listed too.

Input may be gzip, bzip2 or xz compressed, and UTF-8 or UTF-16 (as written
by `cmd /u` or PowerShell), all detected by content, not name. A zip file
(such as collect.zip from collect.bat) is read member by member: listings are
parsed, info.txt supplies the date format and is summarised, and anything
else is skipped. Without --time-label, the timestamp type is taken from
names like *_modified*, *_created* or *_accessed*.
"""

import argparse
import bz2
import calendar
import collections
import csv
import gzip
import io
import itertools
import json
import logging
import lzma
import ntpath
import os
import re
import sys
import time
import zipfile
from datetime import date, datetime, timedelta, timezone

__version__ = "0.2.0"

log = logging.getLogger("shallowtimeline")
VERBOSE = 15  # between INFO and DEBUG
logging.addLevelName(VERBOSE, "VERBOSE")
LINE_WARN_LIMIT = 10  # unparsed-line warnings shown per input below --verbose


class _Formatter(logging.Formatter):
    def format(self, record):
        msg = record.getMessage()
        if record.levelno >= logging.WARNING:
            msg = f"warning: {msg}"
        elif record.levelno < VERBOSE:
            msg = f"debug: {msg}"
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return msg


def setup_logging(quiet, verbose, debug):
    level = (logging.DEBUG if debug else VERBOSE if verbose
             else logging.ERROR if quiet else logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Formatter())
    log.handlers[:] = [handler]
    log.setLevel(level)
    log.propagate = False


class LineWarnings:
    """Per-input warnings about unparsed lines, capped unless --verbose."""

    def __init__(self):
        self.count = 0

    def __call__(self, msg):
        self.count += 1
        if self.count <= LINE_WARN_LIMIT or log.isEnabledFor(VERBOSE):
            log.warning(msg)

    def done(self):
        hidden = self.count - LINE_WARN_LIMIT
        if hidden > 0 and not log.isEnabledFor(VERBOSE):
            log.warning(f"{hidden} more unparsed lines not shown (use --verbose to see all)")


MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}
MON = r"(?:[A-Za-z]{3})\.?"

# Date alternatives, each a named group set. Order matters: most specific first.
DATE_PATTERNS = [
    ("full_iso", r"(?P<fi_date>\d{4}-\d{2}-\d{2}) (?P<fi_time>\d{2}:\d{2}:\d{2})(?P<fi_frac>\.\d+)? (?P<fi_tz>[+-]\d{4})"),
    ("long_iso", r"(?P<li_date>\d{4}-\d{2}-\d{2}) (?P<li_time>\d{2}:\d{2}(?::\d{2})?)"),
    ("bsd_T",    rf"(?P<bt_mon>{MON})\s+(?P<bt_day>\d{{1,2}}) (?P<bt_time>\d{{2}}:\d{{2}}:\d{{2}}) (?P<bt_year>\d{{4}})"),
    ("bsd_T_dm", rf"(?P<bd_day>\d{{1,2}})\s+(?P<bd_mon>{MON}) (?P<bd_time>\d{{2}}:\d{{2}}:\d{{2}}) (?P<bd_year>\d{{4}})"),
    ("md",       rf"(?P<md_mon>{MON})\s+(?P<md_day>\d{{1,2}})\s+(?:(?P<md_time>\d{{1,2}}:\d{{2}})|(?P<md_year>\d{{4}}))"),
    ("dm",       rf"(?P<dm_day>\d{{1,2}})\s+(?P<dm_mon>{MON})\s+(?:(?P<dm_time>\d{{1,2}}:\d{{2}})|(?P<dm_year>\d{{4}}))"),
    ("iso_old",  r"(?P<io_date>\d{4}-\d{2}-\d{2})"),
    ("iso_new",  r"(?P<in_md>\d{2}-\d{2}) (?P<in_time>\d{2}:\d{2})"),
]
DATE_RE = "(?:" + "|".join(p for _, p in DATE_PATTERNS) + ")"

# Size: plain bytes, human-readable (-h), or "major, minor" for device nodes.
SIZE_RE = r"(?P<size>\d+,\s*\d+|0x[0-9a-fA-F]+|\d+(?:\.\d+)?[KMGTPEkB]?)"

# GNU ls puts the ACL/SELinux marker (+ or .) where the space after the mode
# would be, so with a one-digit link-count column there may be no space at
# all: "lrwxrwxrwx+1 root root ...". Whitespace is only optional after a marker.
PERMS_RE = re.compile(
    r"^(?P<perms>[-bcdlpsDnwC?][-rwxsStTlL?]{9})(?P<attr>[.@+]?)(?:(?<=[.@+])\s*|\s+)"
    r"(?P<links>\d+)\s+(?P<rest>.*)$"
)
# Greedy owner/group part is lazy so the *first* plausible size+date wins.
REST_RE = re.compile(
    rf"^(?P<ownergroup>.*?)\s*{SIZE_RE}\s+{DATE_RE} (?P<name>.*)$"
)
TOTAL_RE = re.compile(r"^total\s+\d+(?:\.\d+)?[KMGTPE]?$")

FILE_TYPES = {"-": "file", "d": "dir", "l": "symlink", "c": "chardev",
              "b": "blockdev", "p": "fifo", "s": "socket", "D": "door"}

HUMAN_MULT = {"": 1, "B": 1, "K": 1024, "k": 1024, "M": 1024**2,
              "G": 1024**3, "T": 1024**4, "P": 1024**5, "E": 1024**6}


def month_num(s):
    m = MONTHS.get(s.rstrip(".")[:3].lower())
    if m is None:
        raise ValueError(f"unknown month {s!r}")
    return m


def infer_year(month, day, ref):
    """ls omits the year for recent files; pick the year that keeps the date
    on or before the reference date (with a day of slack for TZ skew)."""
    for year in range(ref.year, ref.year - 8, -1):
        try:
            candidate = date(year, month, day)
        except ValueError:  # Feb 29 outside a leap year
            continue
        if candidate <= ref + timedelta(days=1):
            return year
    raise ValueError(f"cannot infer year for {month:02d}-{day:02d}")


def parse_date(m, ref):
    """Return (datetime, precision, inferred_year) from a REST_RE match."""
    g = m.groupdict()
    if g["fi_date"]:
        s = f"{g['fi_date']} {g['fi_time']}"
        frac = (g["fi_frac"] or "")[1:7].ljust(6, "0") if g["fi_frac"] else "000000"
        dt = datetime.strptime(f"{s}.{frac} {g['fi_tz']}", "%Y-%m-%d %H:%M:%S.%f %z")
        return dt, "subsecond" if g["fi_frac"] else "second", False
    if g["li_date"]:
        fmt = "%Y-%m-%d %H:%M:%S" if g["li_time"].count(":") == 2 else "%Y-%m-%d %H:%M"
        prec = "second" if g["li_time"].count(":") == 2 else "minute"
        return datetime.strptime(f"{g['li_date']} {g['li_time']}", fmt), prec, False
    for p in ("bt", "bd"):
        if g[f"{p}_mon"]:
            hh, mm, ss = map(int, g[f"{p}_time"].split(":"))
            return datetime(int(g[f"{p}_year"]), month_num(g[f"{p}_mon"]),
                            int(g[f"{p}_day"]), hh, mm, ss), "second", False
    for p in ("md", "dm"):
        if g[f"{p}_mon"]:
            mon, day = month_num(g[f"{p}_mon"]), int(g[f"{p}_day"])
            if g[f"{p}_year"]:
                return datetime(int(g[f"{p}_year"]), mon, day), "day", False
            hh, mm = map(int, g[f"{p}_time"].split(":"))
            return datetime(infer_year(mon, day, ref), mon, day, hh, mm), "minute", True
    if g["io_date"]:
        return datetime.strptime(g["io_date"], "%Y-%m-%d"), "day", False
    if g["in_md"]:
        mon, day = map(int, g["in_md"].split("-"))
        hh, mm = map(int, g["in_time"].split(":"))
        return datetime(infer_year(mon, day, ref), mon, day, hh, mm), "minute", True
    raise ValueError("no date matched")


def parse_size(s):
    """Return (bytes_or_None, raw). Device nodes have no byte size."""
    if "," in s:
        return None, re.sub(r"\s+", "", s)
    if s.lower().startswith("0x"):
        return None, s
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGTPEkB]?)", s)
    if m.group(2):
        return int(float(m.group(1)) * HUMAN_MULT[m.group(2)]), s
    return int(m.group(1)), s


def join_path(directory, name):
    if not directory:
        return name
    sep = "\\" if "\\" in directory and "/" not in directory else "/"
    if directory.endswith(sep):
        return directory + name
    return f"{directory}{sep}{name}"


def parse_listing(lines, ref, keep_dots=False, top_dir=""):
    """Yield dict records from an iterable of ls -lR lines.

    top_dir names the directory for entries before the first "dir:" header
    (BSD/macOS ls -R omits the header for the starting directory)."""
    current_dir = top_dir
    warn = LineWarnings()
    debug = log.isEnabledFor(logging.DEBUG)
    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue

        pm = PERMS_RE.match(line)
        if not pm:
            if TOTAL_RE.match(line):
                pass
            elif line.endswith(":"):
                current_dir = line[:-1]
                if debug:
                    log.debug(f"line {lineno}: directory {current_dir!r}")
            else:
                warn(f"line {lineno}: unrecognised: {line!r}")
            continue

        rm = REST_RE.match(pm.group("rest"))
        if not rm:
            warn(f"line {lineno}: could not parse size/date: {line!r}")
            continue
        try:
            dt, precision, inferred = parse_date(rm, ref)
        except ValueError as e:
            warn(f"line {lineno}: bad date ({e}): {line!r}")
            continue

        perms = pm.group("perms")
        ftype = FILE_TYPES.get(perms[0], perms[0])
        name = rm.group("name")
        link_target = ""
        if ftype == "symlink" and " -> " in name:
            name, link_target = name.split(" -> ", 1)
        if ftype == "dir" and name.endswith("/"):  # ls -p / -F
            name = name[:-1]

        if not keep_dots and name in (".", ".."):
            continue

        size_bytes, size_raw = parse_size(rm.group("size"))
        og = rm.group("ownergroup").split()
        owner = og[0] if og else ""
        group = " ".join(og[1:]) if len(og) > 1 else ""

        yield {
            "time": dt,
            "size": size_bytes if size_bytes is not None else size_raw,
            "filename": join_path(current_dir, name),
            "type": ftype,
            "perms": perms + pm.group("attr"),
            "links": int(pm.group("links")),
            "owner": owner,
            "group": group,
            "link_target": link_target,
            "precision": precision,
            "year_inferred": inferred,
            "source_line": lineno,
        }
    warn.done()


# --- Windows cmd.exe `dir /s` -------------------------------------------------

# " Directory of C:\\Users" - the label is localised ("Verzeichnis von", ...),
# so match on a single leading space followed by text and a drive/UNC path.
DIR_HEADER_RE = re.compile(r"^ (?P<label>\S.*?) (?P<path>[A-Za-z]:\\.*|\\\\[^\\].*)$")
DIR_ENTRY_RE = re.compile(
    r"^(?P<d1>\d{1,4})[./-](?P<d2>\d{1,2})[./-](?P<d3>\d{1,4})\.?\s+"
    r"(?P<hh>\d{1,2})[:.](?P<mm>\d{2})(?:\s*(?P<ampm>[AaPp]\.?\s?[Mm]\.?))?\s+"
    r"(?:(?P<tag><[A-Z-]+>)|(?P<size>\d[\d,.\u00a0\u202f]*))\s+(?P<name>.*)$"
)
DIR_TOTAL_RE = re.compile(r"^\s+(?P<n>\d[\d,.\u00a0\u202f]*) (?P<kind>File|Dir)\(s\)")
DIR_TYPES = {"<DIR>": "dir", "<JUNCTION>": "junction", "<SYMLINKD>": "symlink-dir",
             "<SYMLINK>": "symlink", "<MOUNTED-VOLUME>": "mount"}
DIR_LIKE = {"dir", "junction", "symlink-dir", "mount"}
LINK_LIKE = {"junction", "symlink-dir", "symlink", "mount"}


def looks_like_dir_listing(lines):
    return any(DIR_HEADER_RE.match(l) or DIR_ENTRY_RE.match(l) for l in lines)


def to_int(digits):
    return int(re.sub(r"[^\d]", "", digits))


def resolve_date_order(entries, requested, hint=None):
    """Pick the field order for dir's locale-dependent dates. `hint` comes
    from the machine's own date format (info.txt) and settles ambiguity."""
    if requested != "auto":
        log.log(VERBOSE, f"date order: {requested} (from --date-order)")
        return requested
    found = _order_from_data(entries)
    if entries and log.isEnabledFor(VERBOSE):
        log.log(VERBOSE, "date fields: first up to %d, second up to %d; "
                "from data: %s; from info.txt: %s",
                max(int(e["d1"]) for e in entries), max(int(e["d2"]) for e in entries),
                found or "ambiguous", hint or "none")
    if found and hint and found != hint:
        log.warning(f"dates look like {found.upper()} but info.txt says {hint.upper()}; using {found}")
    if found:
        log.log(VERBOSE, f"date order: {found} (from the data)")
        return found
    if hint:
        log.log(VERBOSE, f"date order: {hint} (from info.txt)")
        return hint
    log.warning("could not determine dir date order from the data (no day > 12); "
                "assuming MM/DD/YYYY - pass --date-order if that is wrong")
    return "mdy"


def _order_from_data(entries):
    if not entries:
        return None
    if all(len(e["d1"]) == 4 for e in entries):
        return "ymd"
    max1 = max(int(e["d1"]) for e in entries)
    max2 = max(int(e["d2"]) for e in entries)
    if max1 > 12 and max2 <= 12:
        return "dmy"
    if max2 > 12 and max1 <= 12:
        return "mdy"
    return None


def dir_datetime(e, order):
    a, b, c = int(e["d1"]), int(e["d2"]), int(e["d3"])
    y, mo, d = {"mdy": (c, a, b), "dmy": (c, b, a), "ymd": (a, b, c)}[order]
    if y < 100:
        y += 2000 if y < 80 else 1900
    hh, mm = int(e["hh"]), int(e["mm"])
    ampm = (e["ampm"] or "").lower()
    if ampm.startswith("p") and hh != 12:
        hh += 12
    elif ampm.startswith("a") and hh == 12:
        hh = 0
    return datetime(y, mo, d, hh, mm)


def parse_dir_listing(lines, date_order="auto", keep_dots=False, skipped=None,
                      drop_followed=False, order_hint=None):
    """Yield dict records from Windows `dir /s` output.

    Entries are buffered so the locale's date order can be worked out from
    the whole listing before any dates are converted. Directories that were
    listed but never descended into are appended to `skipped` as
    (path, entry, order) tuples. With drop_followed, entries reached through
    a followed directory symlink whose target was also listed are dropped."""
    current_dir = ""
    headers = set()
    entries = []
    counted = {"File": 0, "Dir": 0}
    totals = {}
    in_totals = False
    warn = LineWarnings()
    debug = log.isEnabledFor(logging.DEBUG)
    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        m = DIR_ENTRY_RE.match(line)
        if m:
            e = m.groupdict()
            e["lineno"] = lineno
            e["dir"] = current_dir
            entries.append(e)
            counted["Dir" if DIR_TYPES.get(e["tag"]) in DIR_LIKE else "File"] += 1
            continue
        h = DIR_HEADER_RE.match(line)
        if h:
            current_dir = h.group("path")
            headers.add(current_dir.lower())
            if debug:
                log.debug(f"line {lineno}: directory {current_dir!r}")
            continue
        if line.strip().startswith("Total Files Listed"):
            in_totals = True
            continue
        t = DIR_TOTAL_RE.match(line)
        if t:
            if in_totals:
                totals[t.group("kind")] = to_int(t.group("n"))
            continue
        # Volume banner and localised summary lines are indented; anything
        # flush-left that isn't an entry is unexpected.
        if not line.startswith(" "):
            warn(f"line {lineno}: unrecognised: {line!r}")
        elif debug:
            log.debug(f"line {lineno}: ignored {line.strip()!r}")

    for kind in ("File", "Dir"):
        if kind in totals and totals[kind] != counted[kind]:
            log.warning(f"dir reports {totals[kind]} {kind}(s) but {counted[kind]} were parsed")
    if totals and all(totals.get(k) == counted[k] for k in totals):
        log.info(f"dir totals check OK: {counted['File']} files, {counted['Dir']} dirs")
    elif not totals:
        log.log(VERBOSE, "no 'Total Files Listed' summary found (truncated listing?); "
                "counts not checked")
    log.log(VERBOSE, f"{len(headers)} 'Directory of' sections")

    if drop_followed:
        entries = drop_followed_links(entries, headers)
    order = resolve_date_order(entries, date_order, order_hint)
    if skipped is not None:
        # dir /s never follows junctions, and follows directory symlinks only
        # when they resolve locally, so only plain <DIR> entries are expected
        # to have a section of their own.
        for e in entries:
            if e["tag"] == "<DIR>" and e["name"] not in (".", ".."):
                path = join_path(e["dir"], e["name"])
                if path.lower() not in headers:
                    skipped.append((path, e, order))
    for e in entries:
        name = e["name"]
        ftype = DIR_TYPES.get(e["tag"], (e["tag"] or "<file>").strip("<>").lower())
        if e["tag"] is None:
            ftype = "file"
        if not keep_dots and name in (".", ".."):
            continue
        link_target = ""
        if ftype in LINK_LIKE and name.endswith("]") and " [" in name:
            name, link_target = name[:-1].rsplit(" [", 1)
        try:
            dt = dir_datetime(e, order)
        except ValueError as ex:
            warn(f"line {e['lineno']}: bad date ({ex}) with order {order}")
            continue
        yield {
            "time": dt,
            "size": to_int(e["size"]) if e["size"] else None,
            "filename": join_path(e["dir"], name),
            "type": ftype,
            "perms": "",
            "links": "",
            "owner": "",
            "group": "",
            "link_target": link_target,
            "precision": "minute",
            "year_inferred": False,
            "source_line": e["lineno"],
        }
    warn.done()


def drop_followed_links(entries, headers):
    """Remove entries listed under a followed <SYMLINKD> whose target has
    its own "Directory of" section, i.e. the same files seen twice."""
    via = []
    for e in entries:
        if e["tag"] != "<SYMLINKD>" or not e["name"].endswith("]") or " [" not in e["name"]:
            continue
        name, target = e["name"][:-1].rsplit(" [", 1)
        link = join_path(e["dir"], name).lower()
        target = ntpath.normpath(ntpath.join(e["dir"], target)).lower()
        followed, listed = link in headers, target in headers
        log.debug(f"symlink {link} -> {target}: followed={followed}, target listed={listed}")
        if followed and listed:
            via.append(link)
    if not via:
        return entries
    def under(d):
        d = d.lower()
        return any(d == v or d.startswith(v.rstrip("\\") + "\\") for v in via)
    kept = [e for e in entries if not under(e["dir"])]
    log.info(f"dropped {len(entries) - len(kept)} entries reached through followed "
             f"symlinks: {', '.join(via)}")
    if log.isEnabledFor(VERBOSE):
        for v in via:
            n = sum(1 for e in entries if under(e["dir"]) and
                    (e["dir"].lower() == v or e["dir"].lower().startswith(v + "\\")))
            log.log(VERBOSE, f"    {v}: {n} entries")
    return kept


def parse_input(lines, args, skipped=None, order_hint=None):
    """Detect the listing format from its first lines and dispatch."""
    lines = iter(lines)
    head = list(itertools.islice(lines, 50))
    fmt = args.input_format
    if fmt == "auto":
        stripped = [l.rstrip("\r\n") for l in head]
        fmt = "dir" if looks_like_dir_listing(stripped) else "ls"
        why = next((f"line {i}: {l!r}" for i, l in enumerate(stripped, 1)
                    if DIR_HEADER_RE.match(l) or DIR_ENTRY_RE.match(l)), "no dir-style lines")
        log.debug(f"format detection from first {len(head)} lines -> {fmt} ({why})")
        log.info(f"input format: {fmt}")
    lines = itertools.chain(head, lines)
    if fmt == "dir":
        return parse_dir_listing(lines, args.date_order, args.keep_dots, skipped,
                                 args.drop_followed_links, order_hint)
    log.log(VERBOSE, f"ls reference date for missing years: {args.ref_date}")
    return parse_listing(lines, args.ref_date, args.keep_dots, args.top_dir)


# --- input decoding -------------------------------------------------------------

COMPRESSORS = [
    (b"\x1f\x8b", "gzip", lambda f: gzip.GzipFile(fileobj=f)),
    (b"BZh", "bzip2", bz2.BZ2File),
    (b"\xfd7zXZ\x00", "xz", lzma.LZMAFile),
]


def sniff_encoding(head):
    """Guess the text encoding from the first bytes. `cmd /u` writes UTF-16LE
    with no BOM, so fall back to looking for the alternating NUL pattern."""
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    pairs = len(head) // 2
    if pairs >= 2:
        even = sum(1 for i in range(0, pairs * 2, 2) if head[i] == 0)
        odd = sum(1 for i in range(1, pairs * 2, 2) if head[i] == 0)
        if odd > pairs * 0.4 and even < pairs * 0.05:
            return "utf-16-le"
        if even > pairs * 0.4 and odd < pairs * 0.05:
            return "utf-16-be"
    return "utf-8"


def open_input(binary):
    """Wrap a buffered binary stream as text, decompressing and detecting the
    encoding from the leading bytes. Returns (text_stream, description)."""
    head = binary.peek(6)[:6]
    comp = None
    for magic, name, opener in COMPRESSORS:
        if head.startswith(magic):
            binary = io.BufferedReader(opener(binary))
            comp = name
            break
    sample = binary.peek(4096)[:4096]
    enc = sniff_encoding(sample)
    log.debug(f"first bytes {sample[:16].hex(' ')} ({len(sample)} sampled) -> "
              f"{comp or 'uncompressed'}, {enc}")
    desc = ", ".join(x for x in (comp and f"{comp} compressed",
                                 enc != "utf-8" and enc) if x) or None
    return io.TextIOWrapper(binary, encoding=enc, errors="surrogateescape"), desc


LABELS = [(r"modif|mtime|write", "mtime"), (r"creat|btime|birth", "btime"),
          (r"access|atime", "atime"), (r"change|ctime", "ctime")]


def label_from_name(name):
    """Timestamp type from a listing's file name, e.g. dir_C_created.txt."""
    base = ntpath.basename(name.replace("/", "\\")).lower()
    for pattern, label in LABELS:
        if re.search(pattern, base):
            return label
    return ""


def parse_info(text):
    """Pull the useful fields out of collect.bat's info.txt."""
    info = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"(start|end) (.*)", line)
        if m:
            info[m.group(1)] = m.group(2).strip()
        elif line.startswith("elevated="):
            info["elevated"] = line.split("=", 1)[1].strip()
        elif line.startswith("listed="):
            info["listed"] = line.split("=", 1)[1].strip()
        elif re.match(r"sShortDate\s+REG_SZ\s+", line):
            info["date_format"] = line.split(None, 2)[2]
        elif re.match(r"sTimeFormat\s+REG_SZ\s+", line):
            info["time_format"] = line.split(None, 2)[2]
        elif line.startswith("Microsoft Windows"):
            info["version"] = line
        elif line.startswith("Drives:"):
            info["drives"] = line.split(":", 1)[1].strip()
        elif "\\" in line and " " not in line and "user" not in info:
            info["user"] = line  # whoami: DOMAIN\user
        elif re.fullmatch(r"[A-Za-z0-9-]{1,63}", line) and "host" not in info:
            info["host"] = line
        elif re.search(r"(Standard|Daylight) Time|UTC", line) and "tz" not in info:
            info["tz"] = line
    fmt = info.get("date_format", "")
    pos = {k: fmt.find(k) for k in "Mdy"}
    if all(v >= 0 for v in pos.values()):
        info["date_order"] = "".join(sorted("mdy", key=lambda k: pos[k.upper() if k == "m" else k]))
    return info


def zip_members(zf, path):
    """Yield (src, member_name, kind) for each zip member, info files first.
    kind is "info", "listing" or None (skipped)."""
    items = [i for i in zf.infolist() if not i.is_dir()]
    items.sort(key=lambda i: not i.filename.lower().endswith("info.txt"))
    for i in items:
        log.log(VERBOSE, f"  member {i.filename}: {i.file_size} bytes "
                f"({i.compress_size} compressed), dated {datetime(*i.date_time)}")
    for i in items:
        src = f"{path}!{i.filename}"
        if i.file_size == 0:
            log.info(f"{src}: empty, skipped")
            continue
        if i.filename.lower().endswith("info.txt"):
            yield src, i, "info"
            continue
        yield src, i, "listing"


def is_listing(head):
    lines = [l.rstrip("\r\n") for l in head]
    return looks_like_dir_listing(lines) or any(PERMS_RE.match(l) for l in lines)


def fmt_time(dt, utc):
    if utc and dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(sep="T")


# Sleuth Kit 3.x bodyfile: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
BODY_SLOTS = {"atime": 7, "mtime": 8, "ctime": 9, "btime": 10}


def to_epoch(dt):
    """Bodyfile times are epoch seconds. Listing times are usually the source
    host's local time with no offset, so they are written as if they were
    UTC; view them with `mactime -z UTC` to get the host's wall-clock back."""
    if dt.tzinfo is None:
        return calendar.timegm(dt.timetuple())
    return int(dt.timestamp())


def body_mode(rec):
    if rec["perms"]:
        return rec["perms"]
    first = {"dir": "d", "junction": "d", "symlink-dir": "l", "symlink": "l",
             "mount": "d"}.get(rec["type"], "-")
    return first + "-" * 9


def bodyfile_rows(records):
    """One row per filename, each labelled timestamp in its own column, so
    the mtime and btime listings of one host (dir /t:w and /t:c) merge into
    one line. A path seen again with the same timestamp type starts a new
    row rather than overwriting."""
    rows, by_name, unknown = [], {}, set()
    for rec in records:
        label = rec["timestamp_type"] or "mtime"
        slot = BODY_SLOTS.get(label)
        if slot is None:
            unknown.add(label)
            slot = BODY_SLOTS["mtime"]
        row = by_name.get(rec["filename"])
        if row is None or row[slot] != 0:
            size = rec["size"] if isinstance(rec["size"], int) else 0
            # mactime drops lines whose UID/GID aren't numeric, and decodes
            # %XX escapes in the name field.
            uid, gid = (x if x.isdigit() else "0" for x in (rec["owner"], rec["group"]))
            name = rec["filename"].replace("%", "%25").replace("|", "%7C")
            row = ["0", name, "0", body_mode(rec), uid, gid, size, 0, 0, 0, 0]
            rows.append(row)
            by_name[rec["filename"]] = row
        row[slot] = to_epoch(rec["time"])
    for label in sorted(unknown):
        log.warning(f"time label {label!r} has no bodyfile column; written as mtime")
    return rows


def parse_skew(s):
    """Clock skew such as '300', '-5m', '1h30m' or '2d' -> signed seconds.
    Positive means the source clock was ahead of true time."""
    m = re.fullmatch(r"([+-]?)((?:\d+[smhd]?)+)", s.strip())
    if not m:
        raise argparse.ArgumentTypeError(f"bad skew {s!r}; use seconds or e.g. -5m, 1h30m, 2d")
    units = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
    total = sum(int(n) * units[u] for n, u in re.findall(r"(\d+)([smhd]?)", m.group(2)))
    return -total if m.group(1) == "-" else total


def sort_key(rec):
    dt = rec["time"]
    # Mixed aware/naive can't be compared; compare aware ones in UTC as naive.
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return (dt, rec["filename"])


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Convert `ls -alR` or Windows `dir /s` output into a CSV/JSONL timeline "
                    "(time, size, filename).",
        epilog="Example: shallowtimeline.py -f jsonl --ref-date 2026-10-30 listing.txt > timeline.jsonl",
    )
    ap.add_argument("--version", action="version", version=f"ShallowTimeline {__version__}")
    ap.add_argument("inputs", nargs="*", help="listing files or zips of them, optionally "
                         "gzip/bzip2/xz compressed "
                         "(default: stdin, '-' also means stdin)")
    ap.add_argument("-f", "--format", choices=["csv", "jsonl", "bodyfile"], default="csv",
                    help="output format (default csv); bodyfile is Sleuth Kit mactime input, "
                         "one line per path with each timestamp type in its own column")
    ap.add_argument("-i", "--input-format", choices=["auto", "ls", "dir"], default="auto",
                    help="listing format (default: detect from the first lines)")
    ap.add_argument("--date-order", choices=["auto", "mdy", "dmy", "ymd"], default="auto",
                    help="field order of Windows dir dates (default: detect from the data)")
    ap.add_argument("-o", "--output", help="output file (default: stdout)")
    ap.add_argument("-e", "--extended", action="store_true",
                    help="add type, perms, links, owner, group, link_target, precision, year_inferred, source")
    ap.add_argument("--ref-date", type=lambda s: datetime.strptime(s, "%Y-%m-%d").date(),
                    default=date.today(),
                    help="date the listing was captured, used to infer missing years (default: today)")
    ap.add_argument("--time-label", default="",
                    help="add a 'timestamp_type' column with this value, e.g. mtime/ctime/atime")
    ap.add_argument("--top-dir", default="",
                    help="directory name for entries listed before the first 'dir:' header "
                         "(macOS/BSD ls -R omits it for the starting directory)")
    ap.add_argument("--prefix", default="", help="prepend to every filename, e.g. a hostname or mount root")
    ap.add_argument("--no-sort", action="store_true", help="keep listing order instead of sorting by time")
    ap.add_argument("-r", "--reverse", action="store_true", help="newest first")
    ap.add_argument("--keep-dots", action="store_true", help="include '.' and '..' entries")
    ap.add_argument("--files-only", action="store_true",
                    help="skip directories (and Windows junctions / directory symlinks)")
    ap.add_argument("--utc", action="store_true",
                    help="convert timezone-aware (full-iso) times to UTC")
    ap.add_argument("--skew", type=parse_skew, default=0, metavar="OFFSET",
                    help="how far the source clock was AHEAD of true time, e.g. 300, 5m, "
                         "-1h30m; every timestamp is moved back by this much")
    ap.add_argument("--drop-followed-links", action="store_true",
                    help="drop Windows dir entries reached through a followed directory "
                         "symlink (e.g. C:\\Users\\All Users) when its target is also listed")
    ap.add_argument("--skipped-dirs", metavar="FILE",
                    help="write Windows dir directories that were listed but not read "
                         "(likely access denied) to FILE as CSV")
    noise = ap.add_mutually_exclusive_group()
    noise.add_argument("-q", "--quiet", action="store_true",
                       help="only report errors (no progress, warnings or summaries)")
    noise.add_argument("-v", "--verbose", action="store_true",
                       help="more detail: per-input statistics, date-order reasoning, zip "
                            "contents, every unparsed line and skipped directory")
    noise.add_argument("--debug", action="store_true",
                       help="everything --verbose shows plus a per-line trace, encoding and "
                            "format detection details, and tracebacks on errors")
    args = ap.parse_args(argv)
    # Filenames that weren't valid UTF-8 are carried as surrogates, which the
    # default strict stdout handler (Python < 3.15) refuses to write. Match
    # what -o does, and stop Windows doubling csv's \r\n.
    sys.stdout.reconfigure(encoding="utf-8", errors="surrogateescape", newline="")
    sys.stderr.reconfigure(errors="backslashreplace")
    setup_logging(args.quiet, args.verbose, args.debug)
    started = time.perf_counter()
    log.debug(f"python {sys.version.split()[0]}, options {vars(args)}")

    records = []
    all_skipped = []
    failed = False
    skew = timedelta(seconds=args.skew)
    if args.skew:
        log.info(f"clock skew {args.skew:+d}s: all timestamps moved "
                 f"{'back' if args.skew > 0 else 'forward'} by {abs(skew)}")

    def process(src, fh, label, order_hint=None):
        """Parse one listing stream into `records`."""
        skipped = []
        first = len(records)
        t0 = time.perf_counter()
        filtered = 0
        try:
            for rec in parse_input(fh, args, skipped, order_hint):
                if args.files_only and rec["type"] in DIR_LIKE:
                    filtered += 1
                    continue
                rec["time"] -= skew
                rec["clock_skew"] = args.skew
                rec["source"] = f"{src}:{rec.pop('source_line')}"
                rec["filename"] = args.prefix + rec["filename"]
                rec["timestamp_type"] = label
                records.append(rec)
        except (EOFError, OSError, lzma.LZMAError, UnicodeError, zipfile.BadZipFile) as e:
            # Truncated or corrupt archive: keep what was parsed so far.
            log.error(f"{src}: stopped reading ({type(e).__name__}: {e}); "
                      "keeping entries parsed so far",
                      exc_info=log.isEnabledFor(logging.DEBUG))
        if skipped:
            log.warning(f"{src}: {len(skipped)} directories listed but not read "
                        "(likely access denied - was it run as Administrator?):")
            shown = skipped if log.isEnabledFor(VERBOSE) else skipped[:10]
            for p, _, _ in shown:
                log.info(f"    {p}")
            if len(skipped) > len(shown):
                log.info(f"    ... {len(skipped) - len(shown)} more (use --skipped-dirs FILE "
                         "or --verbose)")
        all_skipped.extend((src, *x) for x in skipped)
        if log.isEnabledFor(VERBOSE):
            mine = records[first:]
            types = collections.Counter(r["type"] for r in mine)
            log.log(VERBOSE, f"{src}: {len(mine)} entries in {time.perf_counter() - t0:.2f}s"
                    + (f", label {label}" if label else "")
                    + (f", {filtered} directories dropped by --files-only" if filtered else ""))
            if mine:
                log.log(VERBOSE, "    by type: " + ", ".join(f"{k} {v}" for k, v in types.most_common()))
                times = [sort_key(r)[0] for r in mine]
                log.log(VERBOSE, f"    time range: {min(times)} -> {max(times)}")
                prec = collections.Counter(r["precision"] for r in mine)
                log.log(VERBOSE, "    precision: " + ", ".join(f"{k} {v}" for k, v in prec.most_common()))
                inferred = sum(1 for r in mine if r["year_inferred"])
                if inferred:
                    log.log(VERBOSE, f"    {inferred} entries had their year inferred "
                            f"from --ref-date {args.ref_date}")

    def process_zip(path, binary):
        zf = zipfile.ZipFile(binary)
        order_hint = None
        for src, member, kind in zip_members(zf, path):
            fh, desc = open_input(zf.open(member))
            with fh:
                if kind == "info":
                    info = parse_info(fh.read())
                    order_hint = order_hint or info.get("date_order")
                    keys = ("host", "user", "tz", "version", "date_format", "start", "end", "elevated")
                    log.info(f"{src}: " + "; ".join(f"{k}={info[k]}" for k in keys if k in info))
                    extra = [k for k in info if k not in keys]
                    if extra:
                        log.log(VERBOSE, f"{src}: " + "; ".join(f"{k}={info[k]}" for k in extra))
                    if info.get("elevated", "").upper() == "NO":
                        log.warning(f"{src}: collection was NOT run as Administrator - "
                                    "expect many skipped directories")
                    continue
                head = list(itertools.islice(fh, 50))
                if not is_listing(head):
                    log.info(f"{src}: not a listing, skipped")
                    continue
                log.info(f"{src}: " + ", ".join(x for x in (desc, "listing") if x))
                label = args.time_label or label_from_name(member.filename)
                process(src, itertools.chain(head, fh), label, order_hint)

    for path in args.inputs or ["-"]:
        src = "<stdin>" if path == "-" else path
        try:
            binary = sys.stdin.buffer if path == "-" else open(path, "rb")
        except OSError as e:
            log.error(f"{src}: cannot open ({e.strerror})")
            failed = True
            continue
        if path != "-":
            log.log(VERBOSE, f"{src}: {os.path.getsize(path)} bytes")
        if binary.peek(4)[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            log.info(f"{src}: zip archive")
            try:
                # zipfile needs to seek, which stdin can't.
                process_zip(src, io.BytesIO(binary.read()) if path == "-" else binary)
            except zipfile.BadZipFile as e:
                log.error(f"{src}: bad zip file ({e})", exc_info=log.isEnabledFor(logging.DEBUG))
            finally:
                if path != "-":
                    binary.close()
            continue
        fh, comp = open_input(binary)
        if comp:
            log.info(f"{src}: {comp}")
        try:
            process(src, fh, args.time_label or label_from_name(src))
        finally:
            if path == "-":
                fh.detach()  # leave sys.stdin open for any later '-'
            else:
                fh.close()

    if args.skipped_dirs:
        with open(args.skipped_dirs, "w", newline="", encoding="utf-8",
                  errors="surrogateescape") as fh:
            w = csv.writer(fh)
            w.writerow(["time", "directory", "source"])
            for src, p, e, order in all_skipped:
                try:
                    t = (dir_datetime(e, order) - skew).isoformat()
                except ValueError:
                    t = ""
                w.writerow([t, args.prefix + p, f"{src}:{e['lineno']}"])
        log.log(VERBOSE, f"wrote {len(all_skipped)} skipped directories to {args.skipped_dirs}")

    if not args.no_sort:
        records.sort(key=sort_key, reverse=args.reverse)

    # Anything dated after the capture day points at a fast clock or
    # timestomping. Year-less ls dates can't show this: inference already
    # pins them at or before --ref-date.
    cutoff = datetime.combine(args.ref_date + timedelta(days=1), datetime.min.time())
    future = [r for r in records if sort_key(r)[0] >= cutoff]
    if future:
        newest = max(future, key=sort_key)
        n = len(future)
        log.warning(f"{n} {'entry is' if n == 1 else 'entries are'} dated after "
                    f"--ref-date {args.ref_date}; "
                    f"newest {fmt_time(newest['time'], args.utc)} {newest['filename']} "
                    "(clock skew? check --skew; or timestomping)")

    fields = ["time", "size", "filename"]
    if any(rec["timestamp_type"] for rec in records):
        fields.insert(1, "timestamp_type")
    if args.extended:
        fields += ["type", "perms", "links", "owner", "group", "link_target",
                   "precision", "year_inferred", "source"]
        if args.skew:
            fields.append("clock_skew")

    out = (open(args.output, "w", newline="", encoding="utf-8", errors="surrogateescape")
           if args.output else sys.stdout)
    try:
        if args.format == "bodyfile":
            rows = bodyfile_rows(records)
            fields = ["MD5", "name", "inode", "mode", "UID", "GID", "size",
                      "atime", "mtime", "ctime", "crtime"]
            for row in rows:
                out.write("|".join(str(x) for x in row) + "\n")
            log.log(VERBOSE, f"{len(records)} entries merged into {len(rows)} bodyfile lines")
        else:
            if args.format == "csv":
                w = csv.writer(out)
                w.writerow(fields)
            for rec in records:
                rec["time"] = fmt_time(rec["time"], args.utc)
                row = {k: rec[k] for k in fields}
                if args.format == "csv":
                    w.writerow([row[k] for k in fields])
                else:
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
    except BrokenPipeError:  # e.g. piped into head
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1
    finally:
        if out is not sys.stdout:
            out.close()

    log.info(f"{len(records)} entries")
    log.log(VERBOSE, f"wrote {args.format} to {args.output or 'stdout'} with columns "
            f"{', '.join(fields)} in {time.perf_counter() - started:.2f}s total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
