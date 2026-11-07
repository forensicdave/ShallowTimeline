# ShallowTimeline

A poor man's filesystem timeline. Feed it the output of `ls -alR` (or any
recursive long listing), or of Windows `dir /s`, and get back a CSV or JSONL
timeline of `time, size, filename`, sorted chronologically, or a Sleuth Kit
bodyfile for `mactime`, plaso and Timesketch. The input format, compression
and text encoding are all detected automatically.

It's useful when all you have from a system is a directory listing: one
pasted into a ticket, collected by a responder over a remote shell, or
captured by a triage script. You get a rough view of what changed and when,
without a disk image.

No dependencies; requires Python 3.8+.

## Install

It's a single file. Either run it in place with `python3 shallowtimeline.py`,
as the examples below do, or put it on your PATH as `shallowtimeline`:

```sh
chmod +x shallowtimeline.py
ln -s "$PWD/shallowtimeline.py" ~/.local/bin/shallowtimeline   # or /usr/local/bin
shallowtimeline --ref-date 2026-10-30 listing.txt > timeline.csv
```

## Quick start

```sh
# On the target system
ls -alR / > listing.txt 2>/dev/null

# Anywhere
python3 shallowtimeline.py --ref-date 2026-10-30 listing.txt > timeline.csv
```

Input:

```
/etc:
total 1234
drwxr-xr-x 140 root root   12288 Oct 28 09:14 .
-rw-r--r--   1 root root    3028 Dec 14 10:22 adduser.conf
-rw-r--r--.  1 root root      14 Mar  9  2023 my file with spaces.txt
lrwxrwxrwx   1 root root      21 Feb 29 01:02 localtime -> /usr/share/zoneinfo/UTC
crw-rw-rw-   1 root root   1,   3 Oct 29 08:00 null
-rwsr-xr-x   1 1000 1000    4.0K Oct  1 12:00 suid_bin

/etc/cron.d:
total 8
-rw-r--r-- 1 root root  102 Sep  5 23:59 evil
```

Output:

```csv
time,size,filename
2023-03-09T00:00:00,14,/etc/my file with spaces.txt
2024-02-29T01:02:00,21,/etc/localtime
2025-12-14T10:22:00,3028,/etc/adduser.conf
2026-09-05T23:59:00,102,/etc/cron.d/evil
2026-10-01T12:00:00,4096,/etc/suid_bin
2026-10-29T08:00:00,"1,3",/etc/null
```

## Usage examples

**JSONL instead of CSV**

```sh
python3 shallowtimeline.py -f jsonl --ref-date 2026-10-30 listing.txt > timeline.jsonl
```

**Sleuth Kit bodyfile** for `mactime`, plaso or Timesketch, so the listing
can join the rest of your evidence:

```sh
python3 shallowtimeline.py -f bodyfile --ref-date 2026-10-30 listing.txt > listing.body
mactime -b listing.body -d -y -z UTC 1971-01-01 > timeline.csv
```

There is one line per path, with each timestamp type in its own column, so
the modified and created listings in a `collect.zip` come out as one line
per file with both `m` and `b` set:

```
0|C:\Windows\System32\drivers\etc\hosts|0|----------|0|0|888|0|1758213540|0|1711997100
```

Timestamps the listing doesn't have are `0`. The `1971-01-01` start date
stops `mactime` printing them as `0000-00-00` rows. Owner and group are kept
only when they're numeric (`ls -n`), because the format requires numeric
UID/GID; names become `0`. Use the CSV with `-e` if you need them. Listing
times carry no UTC offset, so they're written as if they were UTC, and
`-z UTC` gives you the host's wall-clock back. For `--full-time` listings the
offset is known, the epochs are real, and you can pass the real zone instead.

**Extended fields** (type, perms, links, owner, group, link target,
timestamp precision, whether the year was inferred, source file and line):

```sh
python3 shallowtimeline.py -f jsonl -e --time-label mtime --ref-date 2026-10-30 listing.txt
```

```json
{"time": "2024-02-29T01:02:00", "timestamp_type": "mtime", "size": 21, "filename": "/etc/localtime", "type": "symlink", "perms": "lrwxrwxrwx", "links": 1, "owner": "root", "group": "root", "link_target": "/usr/share/zoneinfo/UTC", "precision": "minute", "year_inferred": true, "source": "listing.txt:7"}
```

**Compressed listings** (gzip, bzip2 and xz are detected from the file's
first bytes, so the extension doesn't matter and renamed files still work):

```sh
python3 shallowtimeline.py --ref-date 2026-10-30 listing.txt.gz
python3 shallowtimeline.py --ref-date 2026-10-30 evidence-0042.bin   # actually an .xz
ssh web01 'ls -alR / 2>/dev/null | gzip' | python3 shallowtimeline.py --prefix web01:
```

**Windows `dir /s` listings**

Collect them with [`collect.bat`](collect.bat), run from an **Administrator
Command Prompt** (not PowerShell). Set `OUT` in the file to a USB drive or
network share if one is available. Otherwise it writes to `C:\collect`.
The script:

- checks it's running elevated, and warns and pauses if it isn't
- records the hostname, user, timezone, Windows version, date/time format,
  the drive list, the drives it listed, and start and end times in
  `info.txt`
- finds every **fixed** drive and runs `dir /s` twice on each, once for
  modification times and once for creation times. The output files are
  `dir_<letter>_modified.txt`, `dir_<letter>_created.txt` and
  `dir_<letter>_errors.txt`.
- zips the output and prints its SHA256 hash

It finds fixed drives through PowerShell's `Win32_LogicalDisk`
`DriveType=3`, which works whatever the Windows display language. If
PowerShell is blocked, it falls back to `fsutil`, which only works on English
Windows, and failing that lists just the system drive. The drive `OUT` is on
is skipped unless it's the system drive, so an external USB disk that
reports itself as "fixed" isn't listed. Removable, network and CD drives are
never listed.

If you can't copy a file onto the machine, paste the lines below into the
prompt. **Copy them from this file, not from a terminal**, because a
terminal can break a line in two and turn it into separate, broken
commands. Each line is short and runs on its own, so the paste is safe:

```bat
set ELEV=NO
whoami /groups | findstr "S-1-16-12288 S-1-16-16384" >nul && set ELEV=yes
if %ELEV%==NO echo WARNING: NOT ELEVATED - many folders will be skipped
set OUT=C:\collect
mkdir "%OUT%" 2>nul
pushd "%OUT%"
compact /c /i /q "%OUT%" >nul 2>&1
set K="HKCU\Control Panel\International"
>info.txt echo start %DATE% %TIME%
>>info.txt echo elevated=%ELEV%
>>info.txt whoami
>>info.txt hostname
>>info.txt tzutil /g
>>info.txt echo.
>>info.txt ver
>>info.txt reg query %K% /v sShortDate
>>info.txt reg query %K% /v sTimeFormat
>>info.txt fsutil fsinfo drives
powershell -nop -c "(gcim Win32_LogicalDisk -Filter DriveType=3).DeviceID"
set D=C
cmd /u /c "dir %D%:\ /s /a /-c /t:w >dir_%D%_modified.txt 2>dir_%D%_errors.txt"
cmd /u /c "dir %D%:\ /s /a /-c /t:c >dir_%D%_created.txt 2>nul"
>>info.txt echo end %DATE% %TIME%
tar -a -cf collect.zip *.txt
certutil -hashfile collect.zip SHA256
popd
```

The `powershell` line prints the fixed drives (e.g. `C:` and `D:`). The paste
version doesn't loop over drives itself, so for each drive after `C:`, paste the
`set D=` line and the two `cmd /u` lines again with the letter changed
(`set D=D`) before the `end` line. Every line here is under 85 characters,
so widen the window if it's narrower than that.

What the switches do: `/a` includes hidden and system files, `/-c` leaves
out thousands separators, and `cmd /u` writes UTF-16 so non-English
filenames survive. `/t:w` lists modification time and `/t:c` creation time.

If you'd rather paste a single line, this one does the same job. It works
only when copied from a file or a web page (such as this README); copied from
a terminal it arrives with line breaks and fails. Both drive letters are
hard-coded as `C:`, because `set X=` and `%X%` on one line don't work in cmd:

```bat
mkdir C:\collect & cd /d C:\collect & compact /c /i /q C:\collect >nul & (echo start %DATE% %TIME% & hostname & whoami & tzutil /g & ver & reg query "HKCU\Control Panel\International" /v sShortDate) >info.txt & (whoami /groups | findstr /c:S-1-16-12288 /c:S-1-16-16384 >nul && echo elevated=yes || echo elevated=NO) >>info.txt & cmd /u /c "dir C:\ /s /a /-c /t:w >dir_C_modified.txt 2>dir_C_errors.txt" & cmd /u /c "dir C:\ /s /a /-c /t:c >dir_C_created.txt 2>nul" & cmd /v:on /c "echo end !DATE! !TIME!" >>info.txt & tar -a -cf collect.zip *.txt & certutil -hashfile collect.zip SHA256
```

For another drive, paste the two `cmd /u /c "dir ..."` parts again with the
letter changed before the `end` part. The end time uses `cmd /v:on` and
`!TIME!` because a plain `%TIME%` is expanded when the line is parsed, so it
would show the start time. If all you need is the two listings:

```bat
mkdir C:\collect & cd /d C:\collect & cmd /u /c "dir C:\ /s /a /-c /t:w >dir_C_modified.txt 2>dir_C_errors.txt" & cmd /u /c "dir C:\ /s /a /-c /t:c >dir_C_created.txt 2>nul"
```

Unlike `collect.bat`, the one-liners haven't been exercised on a real
machine yet. They use the same commands, only joined with `&`, but try them on
a test box first.

If there's nowhere to write except the target disk, use one clearly named
folder (not `%TEMP%` or a user profile) and record its path in your notes.
The script NTFS-compresses the folder (`compact /c`) before writing, which
cuts how much deleted-file space gets overwritten. `info.txt`'s start and end
times let you exclude the collection's own activity from the timeline.

Then parse the zip directly. You don't need to extract it first:

```sh
python3 shallowtimeline.py -e --drop-followed-links collect.zip -o C_timeline.csv
```

```
collect.zip: zip archive
collect.zip!info.txt: host=DAVE3D73; tz=E. Australia Standard Time; version=Microsoft Windows [Version 10.0.26100.7171]; date_format=M/d/yyyy; start=Fri 10/30/2026 17:20:51.09; end=Fri 10/30/2026 17:21:25.74
collect.zip!dir_C_created.txt: utf-16-le, listing
input format: dir
dir totals check OK: 200027 files, 141246 dirs
dropped 4450 entries reached through followed symlinks: c:\users\all users
...
collect.zip!dir_C_errors.txt: empty, skipped
collect.zip!dir_C_modified.txt: utf-16-le, listing
...
488469 entries
```

What happens with a zip:

- **Members are read in place**, without extracting anything to disk. The
  source column records `collect.zip!dir_C_modified.txt:123`.
- **`info.txt` is read first.** It's summarised on stderr, and its date format
  (`sShortDate`) is used when the dates themselves are ambiguous. If it says
  `elevated=NO`, you get a warning.
- **The timestamp type comes from each file's name**: `*_modified*` → `mtime`,
  `*_created*` → `btime`, `*_accessed*` → `atime`. So one run gives a single
  timeline covering both timestamps. `--time-label` overrides this. The same
  naming rule applies to plain files too.
- **Anything else is skipped with a note**: empty files, the errors file,
  and files that don't look like a listing.

The listings can also be parsed one at a time:

```sh
python3 shallowtimeline.py -e dir_C_modified.txt -o C_modified.csv
```

If the paste version warns `NOT ELEVATED`, close the window and start again
from a Command Prompt opened with **Run as administrator**. (`collect.bat`
stops and waits for a key instead.) An admin account in a normal prompt
counts as not elevated, because UAC gives it standard-user rights.
`info.txt` records `elevated=yes` or `elevated=NO`.

The parser checks how many entries it read against dir's own
`Total Files Listed` summary, and warns if they differ.

**Skipped directories.** `dir /s` skips any folder it can't open, without
printing an error, and those folders aren't counted in its totals either. The
parser finds them by looking for `<DIR>` entries that never got a
`Directory of` section of their own:

```
warning: dir_C_modified.txt: 203 directories listed but not read (likely access denied - was it run as Administrator?):
    C:\Config.Msi
    C:\PerfLogs
    C:\System Volume Information
    ...
    ... 193 more (use --skipped-dirs FILE)
```

Use `--skipped-dirs skipped.csv` to save the full list (time, directory,
source line). An elevated run still skips a few folders, such as
`System Volume Information`. If `C:\Windows\Temp`, `C:\Windows\Prefetch` or
other users' profiles show up in the list, the collection probably wasn't
elevated. Junction and symlink
targets (`Documents and Settings [C:\Users]`) go in `link_target`.

**Read from stdin / a remote host**

```sh
ssh web01 'ls -alR --full-time /etc /var/www' | python3 shallowtimeline.py --prefix web01: > web01.csv
```

**Combine several hosts into one timeline** (`--prefix` keeps them apart):

```sh
python3 shallowtimeline.py --prefix web01: --ref-date 2026-10-30 web01.txt > a.csv
python3 shallowtimeline.py --prefix db01:  --ref-date 2026-10-28 db01.txt  > b.csv
# Or, if both listings were captured on the same date, in one run:
python3 shallowtimeline.py --ref-date 2026-10-30 web01.txt db01.txt > combined.csv
```

**Merge mtime, ctime and atime listings**

```sh
ls -alR  /home > m.txt   # mtime
ls -alcR /home > c.txt   # ctime
ls -aluR /home > a.txt   # atime
for t in m c a; do
  python3 shallowtimeline.py -f jsonl --time-label ${t}time --ref-date 2026-10-30 $t.txt
done | sort > home.jsonl   # ISO times sort lexically
```

**macOS / BSD listings** don't print a header for the starting directory,
so tell the tool what it was:

```sh
ls -alRT ~/Library > lib.txt
python3 shallowtimeline.py --top-dir ~/Library lib.txt
```

**Other handy options**

```sh
python3 shallowtimeline.py -r listing.txt | head -50      # newest 50 entries
python3 shallowtimeline.py --files-only listing.txt      # skip directories
python3 shallowtimeline.py --no-sort listing.txt         # keep listing order
python3 shallowtimeline.py --utc full-time-listing.txt   # normalise tz-aware times
python3 shallowtimeline.py -q -o out.csv listing.txt     # no warnings, write to file
```

## Options

| Option | Description |
|---|---|
| `inputs` | One or more listing files (plain or gzip/bzip2/xz compressed), or zip files containing them, such as `collect.zip`. Defaults to stdin; `-` also means stdin. |
| `-f, --format {csv,jsonl,bodyfile}` | Output format (default `csv`). `bodyfile` is Sleuth Kit `mactime` input: one line per path, each timestamp type in its own column; `-e` has no effect on it. |
| `-i, --input-format {auto,ls,dir}` | Listing format. Default: detect from the first lines. |
| `--date-order {auto,mdy,dmy,ymd}` | Field order of Windows `dir` dates. Default: detect from the data. |
| `-o, --output FILE` | Write to a file instead of stdout. |
| `-e, --extended` | Add `type, perms, links, owner, group, link_target, precision, year_inferred, source`. |
| `--ref-date YYYY-MM-DD` | Date the listing was captured; used to infer missing years. Default: today. |
| `--time-label LABEL` | Add a `timestamp_type` column, e.g. `mtime`, `ctime`, `atime`. |
| `--top-dir DIR` | Directory for entries before the first `dir:` header (macOS/BSD). |
| `--prefix STR` | Prepend to every filename, e.g. a hostname. |
| `--no-sort` | Keep the original listing order. |
| `-r, --reverse` | Newest first. |
| `--keep-dots` | Include `.` and `..` entries. |
| `--files-only` | Skip directories, including Windows junctions and directory symlinks. |
| `--utc` | Convert timezone-aware (`--full-time`) timestamps to UTC. |
| `--drop-followed-links` | Drop Windows `dir` entries reached through a followed directory symlink (e.g. `C:\Users\All Users`) when the link's target was also listed. |
| `--skipped-dirs FILE` | Write Windows `dir` directories that were listed but not read (likely access denied) to FILE as CSV. |
| `-v, --verbose` | More detail on stderr: file and zip member sizes, entry counts by type, time range, precision and inferred years for each input, how the date order was chosen, entries dropped per followed link, every unparsed line, every skipped directory, and timings. |
| `--debug` | Everything `--verbose` shows, plus a per-line trace (each directory header and ignored line), the first bytes and detected encoding of each input, why the format was detected, each symlink considered by `--drop-followed-links`, and Python tracebacks on errors. Expect tens of thousands of lines for a full disk. |
| `-q, --quiet` | Only report errors, such as a truncated or corrupt file. No progress messages, warnings or summaries. |

## Supported input

Timestamp styles:

| Style | Example | Precision |
|---|---|---|
| Default, recent | `Oct 30 13:17` | minute, year inferred |
| Default, old | `Oct 30  2024` | day |
| Day-first locale | `30 Oct 13:17`, `30 Oct  2024` | as above |
| macOS `ls -T` | `Oct 30 13:17:05 2024` | second |
| GNU `--full-time` | `2026-10-30 13:17:05.123456789 +0000` | sub-second, with timezone |
| `--time-style=long-iso` | `2026-10-30 13:17` | minute |
| `--time-style=iso` | `10-30 13:17`, `2024-10-30` | minute / day |

It also handles:

- filenames containing spaces
- symlinks (`name -> target` is split out, and the target goes in `link_target`)
- device nodes (the size column holds `major,minor`)
- `-h` sizes such as `4.0K` and `1.2M` (converted to approximate bytes)
- permission suffixes `@`, `+` and `.` (ACLs, xattrs, SELinux)
- numeric owners and groups, and `ls -p`/`-F` trailing slashes on directories
- CRLF line endings and filenames that aren't valid UTF-8
- UTF-8 and UTF-16 text, with or without a byte-order mark (`cmd /u`
  output has none)
- gzip, bzip2 and xz compressed input, from a file or stdin. A truncated or
  corrupt archive produces a warning, and the entries read before the damage
  are kept rather than the whole file being discarded

It skips `total` lines, `.` and `..` (unless you pass `--keep-dots`), and
blank lines. Anything else it can't parse produces a warning on stderr with
the line number. The first 10 such warnings per input are shown, followed by
a count of the rest. Use `--verbose` to see them all.

GNU `ls` prints entries it could see but not `stat` (permission denied,
or a stale or unmounted network/VM share) as `d????????? ? ? ? ? ? name`.
These have no size or time, so they're reported as unparsed lines and left
out of the timeline. A large cluster of them under one path, e.g.
`/media/psf`, usually means a share that was disconnected while the listing ran.

## Caveats for analysts

- **Always pass `--ref-date`.** For files changed in roughly the last six
  months, the default `ls` format leaves out the year. The tool picks the
  most recent year that doesn't put the date after the reference date. If
  you leave `--ref-date` out, it uses *today*, and an old listing will come
  out with the wrong years.
- **Precision varies.** Old files in the default format only have a date,
  and those show up as midnight (`T00:00:00`). With `-e`, the `precision`
  column (`day`/`minute`/`second`/`subsecond`) tells you when that midnight
  isn't real.
- **Collect better listings when you can.** `ls -alR --full-time` (GNU) or
  `ls -alRT` (macOS/BSD) gives you seconds and the year, and with
  `--full-time` the timezone too. Better still, see the next section.
- **One timestamp per run.** `ls` shows mtime by default, ctime with `-c`,
  and atime with `-u`. Label each run with `--time-label`.
- **Local time.** Timestamps are in the source system's local timezone
  unless the listing includes an offset (`--full-time`).
- **Windows `dir` dates follow the machine's locale.** `03/04/2026` could be
  either March or April. The order is worked out from the data once any day
  is over 12. If none is, it uses the date format from `info.txt` when
  reading a zip. Failing that, it assumes MM/DD/YYYY and warns, and you
  should confirm it with `--date-order`. If the data and `info.txt`
  disagree, the data wins and you get a warning. `dir` timestamps are only to the minute, in the
  machine's local time, and don't include owners or permissions.
- **Some Windows folders appear twice.** `dir /s` never follows junctions,
  but it does follow directory symlinks that point to a local folder. On a
  standard install, `C:\Users\All Users` → `C:\ProgramData` means everything
  in ProgramData appears twice in the timeline, under both paths.
  `--drop-followed-links` removes the copy reached through the link. It only
  does this when the link's target has its own listing as well, so nothing
  that appears only through the link is lost. It also removes the duplicated
  entries from the skipped-directories report.
- **It's a listing, not an image.** Deleted files, timestomped files, and
  anything `ls` couldn't read won't show up, or won't show up accurately.
  Treat the result as leads, not proof.

## If you can choose the command, choose a better one

ShallowTimeline exists for listings you didn't get to choose. When you do
have a shell on the system, or a mounted image, there are commands that give
you all the timestamps at full precision, already in bodyfile form, with no
parsing step and no guessed years. Use them instead.

**Linux (GNU find).** Every file's atime, mtime and ctime to the second,
plus inode, mode, numeric uid/gid and size:

```sh
find / -xdev -printf '0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|0\n' 2>/dev/null > host.body
mactime -b host.body -d -y -z UTC 1971-01-01 > host.csv
```

`-xdev` stays on one filesystem, so repeat it per mount point (and skip
`/proc` and `/sys`). Linux has no portable birth time, hence the trailing
`0`. `mactime` accepts the fractional seconds `%T@` prints. `-printf` is
GNU-only; busybox and BSD `find` don't have it.

**macOS / BSD (stat).** APFS keeps four timestamps per file, and `stat`
prints them all:

```sh
sudo find / -xdev -exec stat -f '0|%N|%i|%Sp|%u|%g|%z|%a|%m|%c|%B' {} + 2>/dev/null > mac.body
mactime -b mac.body -d -y -z UTC 1971-01-01 > mac.csv
```

`%B` is the birth time, which `ls` never shows. Since macOS 10.15 the system
and data volumes are separate, so run it on `/` and `/System/Volumes/Data`,
and give the terminal Full Disk Access or parts of `~/Library` will be
missing even as root.

**Windows (PowerShell).** All three timestamps, in UTC, with seconds:

```powershell
Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc |
  Export-Csv C:\collect\files.csv -NoTypeInformation -Encoding UTF8
```

That's a plain CSV, not a bodyfile. For the real thing, parse the `$MFT`
with a dedicated tool: `MFTECmd`, KAPE, or plaso. Those also see deleted
entries, `$FILE_NAME` timestamps and the USN journal, none of which any
listing can show.

**Images and dead disks.** Use Sleuth Kit directly: `fls -r -m / image.dd >
body.txt`, then `mactime`. It includes deleted files and works on NTFS,
ext4, HFS+ and APFS (`pstat` first for an APFS pool). plaso's
`log2timeline.py` does the same and adds logs, registry and browser history.

**What a listing can never give you.** No deleted files, no `$MFT`,
`$LogFile` or USN journal on Windows, no `fseventsd` or Spotlight store on
macOS, no `$FILE_NAME` timestamps to detect timestomping. A listing is a
snapshot of what was visible at that moment, to that user. Use it to decide
where to look, then look properly.
