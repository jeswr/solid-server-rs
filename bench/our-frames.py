# AUTHORED-BY Claude Opus 4.8
# Extract the top SELF-time frame ADDRESSES that belong to a given library (default solid-server-rs),
# so they can be symbolicated with atos. Prints "<count> <pct> <hexaddr>".
import gzip, json, sys
from collections import Counter

path = sys.argv[1]
want_lib = sys.argv[2] if len(sys.argv) > 2 else 'solid-server-rs'
d = json.load(gzip.open(path))
libs = d['libs']

addr_count = Counter()
total = 0
for t in d['threads']:
    funcs = t['funcTable']; func_res = funcs['resource']
    frames = t['frameTable']; frame_func = frames['func']; frame_addr = frames['address']
    stacks = t['stackTable']; stack_frame = stacks['frame']
    res = t['resourceTable']; res_lib = res['lib']
    for s in t['samples']['stack']:
        if s is None: continue
        total += 1
        fr = stack_frame[s]; fn = frame_func[fr]; r = func_res[fn]
        if r is None or r < 0: continue
        li = res_lib[r]
        if li is None or li < 0 or li >= len(libs): continue
        if libs[li]['name'] != want_lib: continue
        a = frame_addr[fr]
        if a is not None and a >= 0:
            addr_count[a] += 1

print(f"# total_samples={total} lib={want_lib}")
for a, c in addr_count.most_common(40):
    print(f"{c}\t{100.0*c/total:.3f}\t0x{a:x}")
