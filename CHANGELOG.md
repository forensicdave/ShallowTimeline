# Changelog

## 0.2.0 - 2026-11-08

### Added
- `--skew OFFSET` corrects for a wrong source clock. Positive means the clock
  was ahead; accepts seconds or `5m`, `4m30s`, `-1h30m`, `2d`. Applied to all
  output formats and the `--skipped-dirs` file. With `-e`, a `clock_skew`
  column records the seconds applied.
- Warning for entries dated after `--ref-date`, which indicates a fast clock
  or timestomping. Year-less `ls` dates can't trigger it by design.
- `-f bodyfile`: Sleuth Kit bodyfile output for `mactime`, plaso and
  Timesketch. One line per path with each timestamp type in its own column,
  so mtime and btime listings of the same host merge.
- `collect.bat` and both paste versions record `w32tm /query /status`.
- README: "Clock skew and time zones", "If you can choose the command, choose
  a better one" (`find -printf`, `stat`, PowerShell, `fls`), a single-line
  cmd.exe paste version, and `ls -alR / 2>/dev/null | gzip -c` collection.

### Fixed
- Non-UTF-8 filenames crashed stdout output on Python 3.9-3.14 (`-o` was
  fine). Stdout now uses the same `surrogateescape` handling.
- GNU `ls` ACL/SELinux marker glued to a one-digit link count
  (`lrwxrwxrwx+1 ...`) was rejected as unrecognised.
- "N more unparsed lines" summary printed twice for `dir` listings.
- A missing input file produced a traceback; now a one-line error, the other
  inputs are still processed, and the exit code is 1.

### Changed
- Renamed from `lsr2timeline` to ShallowTimeline / `shallowtimeline.py`.

## 0.1.0 - 2026-10-30

Initial release: `ls -alR` (GNU, BSD/macOS, busybox) and Windows `dir /s`
listings to CSV or JSONL; gzip/bzip2/xz and zip input; UTF-16 detection;
`collect.bat`; skipped-directory and followed-link detection.
