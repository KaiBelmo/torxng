# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build-time helper of torxng/Dockerfile: make the searx/ package of the
official image identical to the repository's searx/ tree.

    python overlay_sync.py <tree searx dir> <image searx dir>

- text files of the tree are normalised to LF (a Windows checkout with
  core.autocrlf=true has CRLF in the working tree; git and the upstream
  image have LF),
- every file of the tree is copied over the image's package,
- files of the image that are not in the tree are deleted (modules removed
  or renamed in the fork must not survive), except version_frozen.py (only
  generated for upstream builds) and __pycache__ (recompiled afterwards),
- the precompressed static assets of the upstream build (*.gz, *.br next to
  html/css/js/svg files) are kept when their source file is unchanged; for a
  changed source the .gz is regenerated and the .br removed (no brotli module
  in the runtime image), so WhiteNoise never serves stale content.
"""

from __future__ import annotations

import filecmp
import gzip
import shutil
import sys
from pathlib import Path

TEXT_SUFFIXES = {
    ".py", ".pyi", ".html", ".js", ".css", ".json", ".md", ".toml", ".txt", ".xml", ".xsl",
    ".yml", ".yaml", ".po", ".pot", ".msg", ".svg", ".map", ".cfg", ".ini", ".sh",
}
KEEP_NAMES = {"version_frozen.py"}
COMPRESSED = (".gz", ".br")


def normalise_lf(path: Path) -> bool:
    data = path.read_bytes()
    if b"\r\n" not in data:
        return False
    path.write_bytes(data.replace(b"\r\n", b"\n"))
    return True


def main(src_dir: str, dst_dir: str) -> int:
    src, dst = Path(src_dir), Path(dst_dir)
    lf = copied = changed = added = removed = regz = rmbr = 0

    src_files = {p.relative_to(src) for p in src.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    for rel in src_files:
        if rel.suffix in TEXT_SUFFIXES and normalise_lf(src / rel):
            lf += 1

    # 1. delete image files that do not exist in the tree
    for path in sorted(p for p in dst.rglob("*") if p.is_file()):
        rel = path.relative_to(dst)
        if "__pycache__" in rel.parts or rel.name in KEEP_NAMES or rel in src_files:
            continue
        if rel.suffix in COMPRESSED and rel.with_suffix("") in src_files:
            continue  # precompressed asset, handled in step 3
        path.unlink()
        removed += 1

    # 2. copy the tree over the image's package, remember changed sources
    changed_sources: set[Path] = set()
    for rel in sorted(src_files):
        target = dst / rel
        if target.exists():
            if filecmp.cmp(src / rel, target, shallow=False):
                continue
            changed += 1
            changed_sources.add(rel)
        else:
            added += 1
            changed_sources.add(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src / rel, target)
        copied += 1

    # 3. precompressed assets of changed sources
    for rel in sorted(changed_sources):
        gz, br = dst / (str(rel) + ".gz"), dst / (str(rel) + ".br")
        if gz.exists():
            with open(dst / rel, "rb") as fin, gzip.GzipFile(gz, "wb", compresslevel=9, mtime=0) as fout:
                shutil.copyfileobj(fin, fout)
            regz += 1
        if br.exists():
            br.unlink()
            rmbr += 1

    print(
        f"overlay_sync: {len(src_files)} tree files ({lf} CRLF->LF), {copied} copied "
        f"({changed} changed, {added} new), {removed} stale image files removed, "
        f"{regz} .gz regenerated, {rmbr} stale .br removed"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
