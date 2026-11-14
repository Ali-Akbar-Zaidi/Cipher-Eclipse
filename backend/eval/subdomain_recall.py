"""
Evaluation metric 1: Subdomain Recall Rate vs. subfinder and Amass combined.

    baseline = names found by subfinder  ∪  names found by Amass (passive)
    Recall   = |found by Cipher Eclipse  ∩  baseline| / |baseline|

This matches the proposal ("subdomain recall relative to subfinder and Amass
combined"). Recall against each tool on its own is also reported, so the
write-up can show which tool contributes what. Either tool may be missing for
a target; the baseline is then whatever tools are available.

Two flavours are reported for every target:

  * discovery recall  - compares the raw name sets (before DNS). This is the
                        apples-to-apples comparison with subfinder, which also
                        reports names whether or not they still resolve.
  * live recall       - (optional, --resolve-baseline) restricts the baseline to
                        names that currently resolve to a public IPv4 address,
                        then checks how many of those we resolved. This is the
                        number that matters for attack-surface coverage, because
                        dead CT entries are not attack surface.

We also report what each side found that the other did not, and the Jaccard
similarity, so the write-up can discuss *why* recall is below 100%
(subfinder and Amass aggregate dozens of sources; we deliberately use only CT
logs, which miss hosts without TLS certificates or behind wildcard certs).
Our tool's run time per domain is recorded too (proposal: "run time per domain").

Everything here is passive: subfinder is passive by default and Amass is run
with `-passive` (both query third-party datasets only), and the optional DNS
step only asks public resolvers.

Usage examples
--------------
  # 1) Produce baseline files yourself, one per tool:
  #      subfinder -d nmap.org -silent -o baselines/nmap.org.subfinder.txt
  #      amass enum -passive -d nmap.org -o baselines/nmap.org.amass.txt
  python -m eval.subdomain_recall nmap.org vulnweb.com --baseline-dir baselines/

  # 2) Let the script run the tools for you (missing files only):
  python -m eval.subdomain_recall nmap.org --baseline-dir baselines/ --run-subfinder --run-amass

  # 3) Re-use saved Cipher Eclipse outputs instead of re-querying crt.sh:
  #      python -m ingestion nmap.org --out ours/nmap.org.json
  python -m eval.subdomain_recall nmap.org --ours-dir ours/ --baseline-dir baselines/

  # Targets can also come from a file (one per line, # comments allowed):
  python -m eval.subdomain_recall --targets-file eval/targets.txt --baseline-dir baselines/

Outputs (default eval/results/):
  subdomain_recall.json   full detail incl. per-target missed/extra names
  subdomain_recall.csv    one row per target, for spreadsheets/plots
  subdomain_recall.md     a Markdown table you can paste into the report

Baseline file naming in --baseline-dir: <domain>.subfinder.txt and
<domain>.amass.txt (any other <domain>.<tool>.txt is included as an extra
source; a plain <domain>.txt counts as "baseline"). Plain hostname lists,
subfinder JSON lines and Amass's "name (FQDN) --> ..." lines are all accepted.

Note on scanme.nmap.org: it is a single host Nmap explicitly allows people to
test against, not a zone with many subdomains. For recall, evaluate its parent
zone (nmap.org) and the Acunetix test zone (vulnweb.com), plus bug-bounty /
VDP domains that permit OSINT research.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import json
import logging
import re
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from ingestion.crtsh import clean_name, normalize_domain
from ingestion.dns_resolver import MAX_RESOLVED, SubdomainResolver
from ingestion.pipeline import run_ingestion

logger = logging.getLogger("eval.recall")

DEFAULT_OUT = Path(__file__).resolve().parent / "results"


# --------------------------------------------------------------------------- #
# Pure metric code (unit-tested)
# --------------------------------------------------------------------------- #
@dataclass
class RecallResult:
    target: str
    ours_count: int
    baseline_count: int
    overlap: int
    recall: float | None                 # None when the baseline is empty
    precision_vs_baseline: float | None  # share of our names the baseline confirms
    jaccard: float | None
    only_ours: list[str] = field(default_factory=list)
    only_baseline: list[str] = field(default_factory=list)
    # Live (resolving) comparison, filled only with --resolve-baseline.
    baseline_live_count: int | None = None
    ours_live_count: int | None = None
    live_overlap: int | None = None
    live_recall: float | None = None
    # Per-tool breakdown: {"subfinder": {"count": n, "recall": r}, "amass": {...}}
    by_source: dict[str, dict[str, float | int | None]] = field(default_factory=dict)
    # Our ingestion run time for this domain (None if loaded from a cached file
    # that predates timing).
    ours_duration_seconds: float | None = None


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def normalize_names(names: Iterable[str], domain: str) -> set[str]:
    """Apply exactly the same cleaning to both tools' output so the comparison is fair."""
    out = set()
    for n in names:
        c = clean_name(n, domain)
        if c:
            out.add(c)
    return out


def compute_recall(
    target: str,
    ours: set[str],
    baseline: set[str],
    *,
    ours_live: set[str] | None = None,
    baseline_live: set[str] | None = None,
    sources: dict[str, set[str]] | None = None,
    duration: float | None = None,
) -> RecallResult:
    inter = ours & baseline
    union = ours | baseline
    res = RecallResult(
        target=target,
        ours_count=len(ours),
        baseline_count=len(baseline),
        overlap=len(inter),
        recall=_ratio(len(inter), len(baseline)),
        precision_vs_baseline=_ratio(len(inter), len(ours)),
        jaccard=_ratio(len(inter), len(union)),
        only_ours=sorted(ours - baseline),
        only_baseline=sorted(baseline - ours),
        ours_duration_seconds=duration,
    )
    for tool, names in sorted((sources or {}).items()):
        res.by_source[tool] = {
            "count": len(names),
            "recall": _ratio(len(ours & names), len(names)),
            "unique_to_tool": len(names - ours - set().union(
                *(v for k, v in sources.items() if k != tool))),
        }
    if ours_live is not None and baseline_live is not None:
        live_inter = ours_live & baseline_live
        res.baseline_live_count = len(baseline_live)
        res.ours_live_count = len(ours_live)
        res.live_overlap = len(live_inter)
        res.live_recall = _ratio(len(live_inter), len(baseline_live))
    return res


def aggregate(results: list[RecallResult]) -> dict[str, float | int | None]:
    """
    Macro average = mean of per-target recall (each target weighs the same).
    Micro average = pooled overlap / pooled baseline (big targets weigh more).
    Report both; they can differ a lot when targets vary in size.
    """
    scored = [r for r in results if r.recall is not None]
    live = [r for r in results if r.live_recall is not None]
    pooled_overlap = sum(r.overlap for r in scored)
    pooled_base = sum(r.baseline_count for r in scored)
    out: dict[str, float | int | None] = {
        "targets": len(results),
        "targets_scored": len(scored),
        "macro_recall": round(sum(r.recall for r in scored) / len(scored), 4) if scored else None,
        "micro_recall": _ratio(pooled_overlap, pooled_base),
    }
    timed = [r.ours_duration_seconds for r in results if r.ours_duration_seconds is not None]
    if timed:
        out["mean_runtime_seconds"] = round(sum(timed) / len(timed), 2)
        out["max_runtime_seconds"] = round(max(timed), 2)
    if live:
        out["macro_live_recall"] = round(sum(r.live_recall for r in live) / len(live), 4)
        out["micro_live_recall"] = _ratio(
            sum(r.live_overlap for r in live), sum(r.baseline_live_count for r in live)
        )
    return out


# --------------------------------------------------------------------------- #
# Data collection
# --------------------------------------------------------------------------- #
def read_name_file(path: Path) -> list[str]:
    """
    Read tool output and return candidate tokens. Accepts plain hostname lists,
    subfinder JSON lines ({"host": ...}) and Amass graph lines such as
    "www.x.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)". Every whitespace
    token is returned; normalize_names() later keeps only in-scope hostnames.
    """
    names = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):  # subfinder -oJ
            try:
                line = json.loads(line).get("host", "")
            except json.JSONDecodeError:
                continue
        names.extend(line.split())
    return names


# Passive-only command lines for each baseline tool.
BASELINE_TOOLS: dict[str, list[str]] = {
    # subfinder only uses passive sources; -all enables every source.
    "subfinder": ["subfinder", "-d", "{domain}", "-silent", "-all"],
    # -passive disables Amass's DNS brute forcing / zone transfers / cert grabbing.
    "amass": ["amass", "enum", "-passive", "-d", "{domain}"],
}
_TOKEN_SPLIT = re.compile(r"\s+")


async def run_baseline_tool(
    tool: str, domain: str, save_to: Path | None, timeout_s: float = 1800
) -> list[str]:
    """Run a passive baseline enumerator as an async subprocess and save its output."""
    cmd = [part.format(domain=domain) for part in BASELINE_TOOLS[tool]]
    exe = shutil.which(cmd[0])
    if not exe:
        raise RuntimeError(f"{tool} not found on PATH")
    proc = await asyncio.create_subprocess_exec(
        exe, *cmd[1:], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"{tool} timed out for {domain}")
    if proc.returncode != 0:
        raise RuntimeError(f"{tool} failed for {domain}: {stderr.decode()[:300]}")
    text = stdout.decode()
    if save_to:
        save_to.parent.mkdir(parents=True, exist_ok=True)
        save_to.write_text(text)
    return [t for t in _TOKEN_SPLIT.split(text) if t]


async def run_subfinder(domain: str, save_to: Path | None, timeout_s: float = 600) -> list[str]:
    """Backwards-compatible wrapper."""
    return await run_baseline_tool("subfinder", domain, save_to, timeout_s)


async def collect_baseline(domain: str, args: argparse.Namespace) -> dict[str, set[str]]:
    """
    Gather each baseline tool's names for `domain`: read saved files first,
    run a tool only if its file is missing and --run-<tool> was given.
    Returns {tool: normalized names}.
    """
    sources: dict[str, set[str]] = {}
    base_dir: Path | None = args.baseline_dir
    if base_dir and base_dir.is_dir():
        for f in sorted(base_dir.glob(f"{domain}.*txt")):
            middle = f.name[len(domain) + 1 : -len(".txt")]
            if f.name == f"{domain}.txt":
                tool = "baseline"
            elif middle and "." not in middle:
                tool = middle
            else:
                continue  # e.g. sub.nmap.org.txt is another target's file
            sources[tool] = normalize_names(read_name_file(f), domain)
    wanted = {"subfinder": getattr(args, "run_subfinder", False),
              "amass": getattr(args, "run_amass", False)}
    for tool, run in wanted.items():
        if run and tool not in sources:
            save_to = base_dir / f"{domain}.{tool}.txt" if base_dir else None
            logger.info("[%s] running %s", domain, tool)
            try:
                sources[tool] = normalize_names(
                    await run_baseline_tool(tool, domain, save_to), domain)
            except RuntimeError as exc:
                logger.warning("[%s] %s unavailable: %s", domain, tool, exc)
    if not sources:
        raise FileNotFoundError(
            f"No baseline for {domain}: put {domain}.subfinder.txt / {domain}.amass.txt in "
            "--baseline-dir, or pass --run-subfinder / --run-amass"
        )
    return sources


def ours_from_ingestion(result: dict) -> tuple[set[str], set[str]]:
    """
    From a run_ingestion() result return (all discovered names, resolved names).
    'Discovered' includes unresolved and cap-skipped names, which is what
    subfinder's output is comparable to.
    """
    resolved = set(result.get("subdomains", {}))
    discovered = resolved | set(result.get("unresolved", {})) | set(result.get("skipped", []))
    return discovered, resolved


async def resolve_live(names: set[str], resolver: SubdomainResolver) -> set[str]:
    """Which of `names` resolve right now? No cap: this is measurement, not a scan."""
    res = await resolver.resolve_many(names, max_resolved=max(len(names), 1))
    return set(res.resolved)


async def evaluate_target(
    target: str,
    args: argparse.Namespace,
    resolver: SubdomainResolver | None,
) -> RecallResult:
    domain = normalize_domain(target)

    # --- our tool ---
    ours_file = args.ours_dir / f"{domain}.json" if args.ours_dir else None
    if ours_file and ours_file.exists():
        ours_result = json.loads(ours_file.read_text())
        logger.info("[%s] loaded our results from %s", domain, ours_file)
    else:
        logger.info("[%s] running Cipher Eclipse ingestion", domain)
        ours_result = await run_ingestion(domain, max_resolved=MAX_RESOLVED)
        if args.ours_dir:
            args.ours_dir.mkdir(parents=True, exist_ok=True)
            ours_file.write_text(json.dumps(ours_result, indent=2))
    duration = (ours_result.get("stats") or {}).get("duration_seconds")
    ours_all, ours_resolved = ours_from_ingestion(ours_result)
    ours_all = normalize_names(ours_all, domain)
    ours_resolved = normalize_names(ours_resolved, domain)

    # --- baseline: union of all tools (subfinder ∪ Amass) ---
    sources = await collect_baseline(domain, args)
    baseline: set[str] = set().union(*sources.values())
    logger.info("[%s] baseline %d names from %s", domain, len(baseline),
                ", ".join(f"{k}={len(v)}" for k, v in sources.items()))

    # --- optional live comparison ---
    if resolver is not None:
        baseline_live = await resolve_live(baseline, resolver)
        return compute_recall(domain, ours_all, baseline,
                              ours_live=ours_resolved, baseline_live=baseline_live,
                              sources=sources, duration=duration)
    return compute_recall(domain, ours_all, baseline, sources=sources, duration=duration)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v * 100:.1f}%"


def write_reports(results: list[RecallResult], summary: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    (out_dir / "subdomain_recall.json").write_text(json.dumps(
        {"generated_at": stamp, "summary": summary, "targets": [asdict(r) for r in results]},
        indent=2,
    ))

    cols = ["target", "ours_count", "baseline_count", "overlap", "recall",
            "precision_vs_baseline", "jaccard", "baseline_live_count",
            "ours_live_count", "live_overlap", "live_recall", "ours_duration_seconds"]
    tools = sorted({t for r in results for t in r.by_source})
    with (out_dir / "subdomain_recall.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols + [f"{t}_{k}" for t in tools
                                                  for k in ("count", "recall")])
        w.writeheader()
        for r in results:
            row = {c: getattr(r, c) for c in cols}
            for t in tools:
                row[f"{t}_count"] = r.by_source.get(t, {}).get("count")
                row[f"{t}_recall"] = r.by_source.get(t, {}).get("recall")
            w.writerow(row)

    tool_hdr = "".join(f" vs {t} |" for t in tools)
    lines = [
        f"# Subdomain Recall vs {' + '.join(tools) or 'baseline'} combined ({stamp})",
        "",
        f"| Target | Ours | Baseline (union) | Overlap | Recall | Live recall | Jaccard |{tool_hdr} Run time |",
        "|---|---:|---:|---:|---:|---:|---:|" + "---:|" * len(tools) + "---:|",
    ]
    for r in results:
        per_tool = "".join(f" {_pct(r.by_source.get(t, {}).get('recall'))} |" for t in tools)
        rt = "n/a" if r.ours_duration_seconds is None else f"{r.ours_duration_seconds:.1f}s"
        lines.append(
            f"| {r.target} | {r.ours_count} | {r.baseline_count} | {r.overlap} | "
            f"{_pct(r.recall)} | {_pct(r.live_recall)} | {_pct(r.jaccard)} |{per_tool} {rt} |"
        )
    lines += [
        "",
        f"**Macro recall:** {_pct(summary.get('macro_recall'))}  ",
        f"**Micro recall:** {_pct(summary.get('micro_recall'))}",
    ]
    if "macro_live_recall" in summary:
        lines += [
            f"  \n**Macro live recall:** {_pct(summary['macro_live_recall'])}  ",
            f"**Micro live recall:** {_pct(summary['micro_live_recall'])}",
        ]
    if "mean_runtime_seconds" in summary:
        lines += [f"  \n**Run time per domain:** mean {summary['mean_runtime_seconds']}s, "
                  f"max {summary['max_runtime_seconds']}s"]
    (out_dir / "subdomain_recall.md").write_text("\n".join(lines) + "\n")


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.targets)
    if args.targets_file:
        for line in args.targets_file.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(line)
    if not targets:
        raise SystemExit("No targets given")
    return list(dict.fromkeys(targets))


async def amain(args: argparse.Namespace) -> int:
    resolver = SubdomainResolver() if args.resolve_baseline else None
    results: list[RecallResult] = []
    for t in load_targets(args):
        try:
            results.append(await evaluate_target(t, args, resolver))
        except Exception as exc:  # keep going; one target failing should not lose the rest
            logger.error("[%s] skipped: %s", t, exc)
    if not results:
        logger.error("No targets could be evaluated")
        return 1
    summary = aggregate(results)
    write_reports(results, summary, args.out_dir)
    print((args.out_dir / "subdomain_recall.md").read_text())
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Subdomain recall of Cipher Eclipse vs subfinder + Amass.")
    p.add_argument("targets", nargs="*", help="Target domains")
    p.add_argument("--targets-file", type=Path)
    p.add_argument("--baseline-dir", type=Path,
                   help="Directory of <domain>.subfinder.txt / <domain>.amass.txt outputs")
    p.add_argument("--run-subfinder", action="store_true", help="Run subfinder if its file is missing")
    p.add_argument("--run-amass", action="store_true",
                   help="Run 'amass enum -passive' if its file is missing")
    p.add_argument("--ours-dir", type=Path, help="Cache/load our results as <domain>.json")
    p.add_argument("--resolve-baseline", action="store_true",
                   help="Also compute live recall (resolves baseline names via public DNS)")
    p.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    return asyncio.run(amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
