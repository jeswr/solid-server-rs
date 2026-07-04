#!/usr/bin/env python3
# AUTHORED-BY Claude Fable 5
"""Render the committed syscalls-per-request report from a bench/syscalls.sh raw dir.

Stdlib-only. Reads the raw artifacts one harness run produced (strace -c tables, driver JSON
summaries, perf stat/report text) and writes the two GENERATED artifacts that get committed:

  - <out-json>: the machine-readable record (the single source of truth for any number cited in
    markdown — per the repo/no-hard-coded-perf rule, prose must cite this file, never inline copies
    of its values);
  - <out-md>:   the human rendering, generated from the same data (header marks it generated).

Deterministic metrics: integer syscall counts / fixed N (per request class, per rep), response
bytes per request. Advisory: everything perf-derived (sampled CPU %, wall-clock-based counters).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time


STRACE_ROW = re.compile(
    # "%time seconds usecs/call calls [errors] syscall"
    r"^\s*\d+(?:\.\d+)?\s+\d+(?:\.\d+)?\s+(\d+)\s+(\d+)(?:\s+(\d+))?\s+(\S+)\s*$"
)


def parse_strace_c(path):
    """Parse a `strace -c` summary table -> (dict syscall -> {calls, errors}, total_calls).

    The total is SUMMED from the per-syscall rows (never read from the ambiguous `total` row).
    """
    rows = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = STRACE_ROW.match(line.rstrip("\n"))
            if not m:
                continue
            _usecs, calls, errors, name = m.groups()
            if name == "total":
                continue
            rows[name] = {"calls": int(calls), "errors": int(errors or 0)}
    return rows, sum(r["calls"] for r in rows.values())


def load_driver_summaries(raw, pass_name):
    """driver-<pass>-<idx>-<scenario>.json -> list of (idx, scenario, summary) sorted by idx."""
    out = []
    pat = re.compile(rf"^driver-{pass_name}-(\d+)-([a-z-]+)\.json$")
    for name in sorted(os.listdir(raw)):
        m = pat.match(name)
        if not m:
            continue
        with open(os.path.join(raw, name), encoding="utf-8") as f:
            out.append((int(m.group(1)), m.group(2), json.load(f)))
    out.sort(key=lambda t: t[0])
    return out


def head_lines(path, limit):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [ln.rstrip() for ln in f]
    kept = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    return kept[:limit]


def kernel_share(dso_report_path):
    """Extract the [kernel.kallsyms] overhead %% from a `perf report --sort dso` dump."""
    for ln in head_lines(dso_report_path, 50):
        if "[kernel" in ln:
            m = re.search(r"(\d+(?:\.\d+)?)%", ln)
            if m:
                return float(m.group(1))
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--perf-n", type=int, required=True)
    ap.add_argument("--warmup", type=int, required=True)
    ap.add_argument("--idle-secs", type=int, required=True)
    ap.add_argument("--children", type=int, required=True)
    ap.add_argument("--git-sha", required=True)
    ap.add_argument("--instance", required=True)
    args = ap.parse_args()
    raw = args.raw

    def sh(cmd):
        try:
            return subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            ).stdout.strip()
        except Exception:
            return "unknown"

    host = {
        "kernel": sh("uname -r"),
        "arch": sh("uname -m"),
        "cpu_model": sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2").strip(),
        "cores": int(sh("nproc") or 0),
        "instance": args.instance,
        "strace": sh("strace -V | head -1"),
        "perf": sh("perf --version"),
        "rustc": sh("rustc --version"),
    }

    # ---- deterministic: the strace pass -----------------------------------------------------------
    scenarios = {}
    idle = None
    for idx, scen, summary in load_driver_summaries(raw, "strace"):
        strace_file = os.path.join(raw, f"strace-{idx}-{scen}.txt")
        if not os.path.exists(strace_file):
            print(f"WARNING: missing {strace_file}", file=sys.stderr)
            continue
        table, total = parse_strace_c(strace_file)
        if scen == "idle":
            secs = summary.get("idle_secs", args.idle_secs)
            idle = {
                "duration_secs": secs,
                "total_syscalls": total,
                "syscalls_per_sec": round(total / secs, 2) if secs else None,
                "by_syscall": {k: v["calls"] for k, v in sorted(table.items())},
            }
            continue
        n = summary["n"]
        rep = {
            "n": n,
            "statuses": summary["statuses"],
            "bytes_per_request": summary["bytes_per_request"],
            "reconnects": summary["reconnects"],
            "total_syscalls": total,
            "syscalls_per_request": round(total / n, 4),
            "by_syscall": {
                name: {
                    "calls": row["calls"],
                    "errors": row["errors"],
                    "per_request": round(row["calls"] / n, 4),
                }
                for name, row in sorted(
                    table.items(), key=lambda kv: -kv[1]["calls"]
                )
            },
        }
        scenarios.setdefault(scen, {"reps": []})["reps"].append(rep)

    # ---- advisory: the perf pass -------------------------------------------------------------------
    perf = {}
    for idx, scen, summary in load_driver_summaries(raw, "perf"):
        stat_file = os.path.join(raw, f"perfstat-{idx}-{scen}.txt")
        dso_file = os.path.join(raw, f"perf-{idx}-{scen}-dso.txt")
        sym_file = os.path.join(raw, f"perf-{idx}-{scen}-symbols.txt")
        perf[scen] = {
            "n": summary.get("n"),
            "kernel_cpu_percent": kernel_share(dso_file),
            "perf_stat": head_lines(stat_file, 25),
            "top_dso": head_lines(dso_file, 8),
            "top_symbols": head_lines(sym_file, 20),
        }

    report = {
        "kind": "solid-server-rs syscalls-per-request (Linux)",
        "generated_by": "bench/syscalls.sh + bench/syscalls-report.py",
        "generated_unix": int(time.time()),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_sha": args.git_sha,
        "host": host,
        "params": {
            "n": args.n,
            "perf_n": args.perf_n,
            "warmup": args.warmup,
            "idle_secs": args.idle_secs,
            "listing_children": args.children,
            "transport": "plain HTTP/1.1, single keep-alive connection, loopback",
            "store": "in-memory doubles (PSS_SPARQ_BACKEND=memory), bench-seeded",
            "auth": "mock loopback OIDC issuer; DPoP-bound at+jwt; token cache ON (default)",
        },
        "metric_classes": {
            "deterministic": [
                "scenarios.*.reps[].by_syscall.*.calls / per_request",
                "scenarios.*.reps[].total_syscalls / syscalls_per_request",
                "scenarios.*.reps[].bytes_per_request",
            ],
            "advisory": ["perf.* (sampled CPU shares, perf stat counters)"],
        },
        "caveats": [
            "strace slows the traced server heavily; reactor-amortized syscalls (epoll_wait, "
            "timer maintenance) can BATCH differently under trace — per-request I/O syscalls "
            "(read/recvfrom/write/sendto/writev) are robust, amortized ones are approximate.",
            "idle_baseline shows the background syscall rate the counts sit on; at the configured "
            "N its contribution per request is negligible but nonzero.",
            "t3-class EC2 exposes no hardware PMU: perf uses software counters/cpu-clock sampling.",
        ],
        "idle_baseline": idle,
        "scenarios": scenarios,
        "perf_advisory": perf,
    }

    os.makedirs(os.path.dirname(args.out_json), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=False)
        f.write("\n")

    # ---- markdown rendering (generated; numbers all sourced from the JSON above) -------------------
    md = []
    md.append(f"# solid-server-rs — Linux syscalls-per-request ({report['generated_utc'][:10]})")
    md.append("")
    md.append(
        f"> **GENERATED** by `bench/syscalls.sh` (do not hand-edit; re-run to refresh). "
        f"Machine-readable source of truth: [`{os.path.basename(args.out_json)}`]({os.path.basename(args.out_json)}). "
        f"Server `{args.git_sha}`, {host['instance']}, kernel `{host['kernel']}` ({host['arch']}), "
        f"{host['cores']} cores, {host['cpu_model']}."
    )
    md.append("")
    md.append(
        f"Methodology: fixed-N single-keep-alive-connection request script per class "
        f"(N={args.n}, warm-up {args.warmup} untraced), `strace -f -c` attached to the warm "
        f"quiesced server only for the measured window; counts/N = per-request. Deterministic "
        f"metrics = integer syscall counts + response bytes; perf sections are **ADVISORY** "
        f"(wall-clock/sampling — never a gate, per the perf-gate rule). See `bench/SYSCALLS.md`."
    )
    md.append("")

    if idle:
        md.append("## Idle noise floor")
        md.append("")
        md.append(
            f"- {idle['total_syscalls']} syscalls over {idle['duration_secs']}s idle "
            f"(≈ {idle['syscalls_per_sec']}/s) — the background (timer/epoll) rate the "
            f"per-request counts sit on."
        )
        top_idle = sorted(idle["by_syscall"].items(), key=lambda kv: -kv[1])[:5]
        md.append(
            "- top idle syscalls: "
            + ", ".join(f"`{k}` ({v})" for k, v in top_idle)
        )
        md.append("")

    md.append("## Deterministic: syscalls per request, by class")
    md.append("")
    order = ["anon-doc", "listing", "authed-doc", "put"]
    md.append("| class | rep | N | status | bytes/req | total syscalls | **syscalls/req** |")
    md.append("|---|---|---|---|---|---|---|")
    for scen in order:
        for i, rep in enumerate(scenarios.get(scen, {}).get("reps", []), 1):
            status = ",".join(f"{k}×{v}" for k, v in rep["statuses"].items())
            md.append(
                f"| {scen} | {i} | {rep['n']} | {status} | {rep['bytes_per_request']:.0f} "
                f"| {rep['total_syscalls']} | **{rep['syscalls_per_request']:.2f}** |"
            )
    md.append("")

    for scen in order:
        reps = scenarios.get(scen, {}).get("reps", [])
        if not reps:
            continue
        md.append(f"### {scen} — per-syscall breakdown (rep 1)")
        md.append("")
        md.append("| syscall | calls | errors | per request |")
        md.append("|---|---|---|---|")
        for name, row in list(reps[0]["by_syscall"].items())[:14]:
            md.append(
                f"| `{name}` | {row['calls']} | {row['errors']} | {row['per_request']:.3f} |"
            )
        md.append("")

    if perf:
        md.append("## Advisory: CPU profile (perf, sampled — NOT a gate)")
        md.append("")
        md.append(
            f"Untraced windows of N={args.perf_n} per class under `perf stat` + "
            f"`perf record -g -e cpu-clock` (software counters; no PMU on this instance class)."
        )
        md.append("")
        md.append("| class | kernel CPU share (sampled) |")
        md.append("|---|---|")
        for scen in order:
            p = perf.get(scen)
            if not p:
                continue
            ks = f"{p['kernel_cpu_percent']:.1f}%" if p.get("kernel_cpu_percent") is not None else "n/a"
            md.append(f"| {scen} | {ks} |")
        md.append("")
        for scen in order:
            p = perf.get(scen)
            if not p or not p.get("top_symbols"):
                continue
            md.append(f"### {scen} — top sampled symbols (advisory)")
            md.append("")
            md.append("```")
            md.extend(p["top_symbols"][:15])
            md.append("```")
            md.append("")

    md.append("## Caveats")
    md.append("")
    for c in report["caveats"]:
        md.append(f"- {c}")
    md.append("")

    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"wrote {args.out_json} and {args.out_md}")


if __name__ == "__main__":
    main()
