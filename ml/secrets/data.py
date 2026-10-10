"""CredData loader: one record per labelled credential candidate, with the value, its line and its context.

Layout produced by the CredData download script (on E:\\MEDIANET ML\\secrets\\creddata):
  meta_after/<repo>.csv   one row per candidate (GroundTruth T / F / X, ValueStart/ValueEnd, Category)
  data/<repo>/<scope>/<fileid>.<ext>   the (obfuscated) source files; FilePath in the csv is relative to creddata/

Labels: T = looks like a real credential. F = false positive. X = test value / example / placeholder.
For Medianet "real secret" is T; F and X are both "not a real secret" by default (variant: drop X).
"""
from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Iterable

import pandas as pd

DEFAULT_ROOT = Path(r"E:\MEDIANET ML\secrets\creddata")
CONTEXT_LINES = 3
MAX_VALUE_CHARS = 400
MAX_LINE_CHARS = 600


def _read_lines(path: Path) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n]


def build_record(row: dict, lines: list[str]) -> dict | None:
    """Turn one meta row + the file's lines into a record; None when the line cannot be found."""
    try:
        start = int(row["LineStart"])
        end = int(row["LineEnd"])
    except (TypeError, ValueError):
        return None
    if not lines or start < 1 or end < start or end > len(lines):
        return None

    first_line = lines[start - 1]
    vs, ve = row.get("ValueStart"), row.get("ValueEnd")
    value = ""
    try:
        if vs not in (None, "", "-1") and start == end:
            a = int(vs)
            b = int(ve) if ve not in (None, "", "-1") else len(first_line)
            value = first_line[a:b]
        elif vs not in (None, "", "-1"):
            value = "\n".join(lines[start - 1:end])
    except ValueError:
        value = ""
    value_start = -1
    value_end = -1
    if vs not in (None, "", "-1") and start == end:
        try:
            value_start = int(vs)
            value_end = int(ve) if ve not in (None, "", "-1") else len(first_line)
        except ValueError:
            pass
    whole_line = value == ""  # markup of the whole line (False cases): no value span available
    if whole_line:
        value = first_line.strip()
    before = lines[max(0, start - 1 - CONTEXT_LINES):start - 1]
    after = lines[end:end + CONTEXT_LINES]
    path = row["FilePath"]
    return {
        "repo": row["RepoName"],
        "path": path,
        "ext": os.path.splitext(path)[1].lower(),
        "line_no": start,
        "value": _clip(value, MAX_VALUE_CHARS),
        "whole_line": whole_line,
        "vs": value_start,
        "ve": value_end,
        "line": _clip(first_line, MAX_LINE_CHARS),
        "before": _clip("\n".join(before), MAX_LINE_CHARS * CONTEXT_LINES),
        "after": _clip("\n".join(after), MAX_LINE_CHARS * CONTEXT_LINES),
        "category": row.get("Category", "") or "",
        "predefined": row.get("PredefinedPattern", "") or "",
        "crypto_key": row.get("CryptographyKey", "") or "",
        "truth": row["GroundTruth"],
    }


def load_creddata(root: Path = DEFAULT_ROOT, limit_repos: int | None = None) -> pd.DataFrame:
    meta_dir = Path(root) / "meta_after"
    files = sorted(meta_dir.glob("*.csv"))
    if limit_repos:
        files = files[:limit_repos]
    records: list[dict] = []
    skipped = 0
    for meta in files:
        with open(meta, "r", encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        cache: dict[str, list[str]] = {}
        for row in rows:
            fp = row["FilePath"]
            if fp not in cache:
                cache[fp] = _read_lines(Path(root) / fp)
            rec = build_record(row, cache[fp])
            if rec is None:
                skipped += 1
                continue
            records.append(rec)
    df = pd.DataFrame.from_records(records)
    df.attrs["skipped"] = skipped
    return df


def clean(df: pd.DataFrame, drop_unknown: bool = False, require_span: bool = True) -> pd.DataFrame:
    """Binary label + de-duplication. y=1 is a real secret (T); F and X are 0 unless drop_unknown.

    require_span: CredData marks most False rows as a whole line (no value span; 68% of F, ~1% of T). Keeping them
    would let a model learn "no span => False", which a scanner never gives at inference. They are dropped.
    """
    out = df.copy()
    if require_span:
        out = out[~out["whole_line"]]
    if drop_unknown:
        out = out[out["truth"] != "X"]
    out = out[out["truth"].isin(["T", "F", "X"])]
    out["y"] = (out["truth"] == "T").astype(int)
    # the same candidate listed twice in a repo (several detectors flagged it) must not count twice
    out = out.drop_duplicates(subset=["repo", "value", "line", "y"]).reset_index(drop=True)
    return out


def groups(df: pd.DataFrame) -> Iterable[str]:
    return df["repo"]


# ───────────────────────── what a scanner really provides ─────────────────────────

_ASSIGN_LEFT = None


def match_like(line: str, vs: int, ve: int) -> str:
    """Approximates Gitleaks' ``Match``: the key name, the separator and the (quoted) value, not the whole line.

    Gitleaks gives no surrounding lines either, so the deployable model must work from this alone."""
    import re
    global _ASSIGN_LEFT
    if _ASSIGN_LEFT is None:
        _ASSIGN_LEFT = re.compile(r"([\"'`]?[\w.\-\[\]]+[\"'`]?)\s*(?:=>|:=|==|=|:)\s*[\"'`]?$")
    if vs < 0:
        return line.strip()
    left = line[:vs]
    m = _ASSIGN_LEFT.search(left)
    begin = m.start(1) if m else max(0, vs - 1)
    end = ve + 1 if ve < len(line) and line[ve] in "\"'`" else ve
    return line[begin:end]


def gitleaks_view(df: pd.DataFrame) -> pd.DataFrame:
    """Same rows as a scanner report: match + value + path (no context lines, no neighbouring code)."""
    out = df.copy()
    out["line"] = [match_like(l, a, b) for l, a, b in zip(out["line"], out["vs"], out["ve"])]
    out["before"] = ""
    out["after"] = ""
    return out
