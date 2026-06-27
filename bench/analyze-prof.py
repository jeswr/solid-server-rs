# AUTHORED-BY Claude Opus 4.8
# Analyze a samply (Firefox Profiler) gzipped profile. Two views:
#   1. SELF time attributed to LIBRARY (our binary vs TLS/kernel/malloc/etc) — the macro split.
#   2. SELF time by symbolicated function name where available, and by (lib + address) where not.
import gzip, json, sys
from collections import Counter

path = sys.argv[1]
d = json.load(gzip.open(path))
libs = d['libs']

self_lib = Counter()
self_func = Counter()      # (libname, funcdisplay) -> count
total = 0

for t in d['threads']:
    strings = t.get('stringArray') or t['stringTable']
    funcs = t['funcTable']
    func_name = funcs['name']
    func_res = funcs['resource']      # func idx -> resource idx (-1 if none)
    frames = t['frameTable']
    frame_func = frames['func']
    stacks = t['stackTable']
    stack_frame = stacks['frame']
    samples = t['samples']
    res = t['resourceTable']
    res_lib = res['lib']              # resource idx -> lib idx (or None)
    res_name = res['name']            # resource idx -> string idx

    def libname_for_func(fn):
        r = func_res[fn]
        if r is None or r < 0:
            return '(none)'
        li = res_lib[r]
        if li is not None and li >= 0 and li < len(libs):
            return libs[li]['name']
        # fall back to the resource's own name
        return strings[res_name[r]]

    for s in samples['stack']:
        if s is None:
            continue
        total += 1
        fr = stack_frame[s]
        fn = frame_func[fr]
        ln = libname_for_func(fn)
        self_lib[ln] += 1
        nm = strings[func_name[fn]]
        self_func[(ln, nm)] += 1

print(f"# total samples: {total}   profile: {path}\n")
print("=== SELF time by LIBRARY (macro split) ===")
for ln, c in self_lib.most_common(20):
    print(f"{100.0*c/total:6.2f}%  {c:8d}  {ln}")

print("\n=== SELF time by (lib, function/addr) top 40 ===")
for (ln, nm), c in self_func.most_common(40):
    disp = nm if len(nm) <= 70 else nm[:67]+'...'
    print(f"{100.0*c/total:6.2f}%  {c:7d}  [{ln[:24]:24s}] {disp}")
