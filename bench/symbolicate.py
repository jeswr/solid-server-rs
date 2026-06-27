# AUTHORED-BY Claude Opus 4.8
# Symbolicate the top SELF-time solid-server-rs frames of a samply profile via atos. Prints
# "<pct>  <symbol>" sorted by self-time. The samply frameTable.address is the lib-relative offset;
# the binary's __TEXT vmaddr is 0x100000000, so the runtime addr = 0x100000000 + reladdr and atos is
# called with -l 0x100000000.
import gzip, json, sys, subprocess
from collections import Counter

path = sys.argv[1]
binpath = sys.argv[2] if len(sys.argv) > 2 else 'target/release/solid-server-rs'
topn = int(sys.argv[3]) if len(sys.argv) > 3 else 40
d = json.load(gzip.open(path))
libs = d['libs']
TEXT = 0x100000000

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
        if libs[li]['name'] != 'solid-server-rs': continue
        a = frame_addr[fr]
        if a is not None and a >= 0:
            addr_count[a] += 1

top = addr_count.most_common(topn)
full = [hex(TEXT + a) for a, _ in top]
out = subprocess.run(['atos', '-o', binpath, '-arch', 'arm64', '-l', '0x100000000'] + full,
                     capture_output=True, text=True).stdout.splitlines()
print(f"# total_samples={total}  our-code frames (self-time)\n")
for (a, c), sym in zip(top, out):
    print(f"{100.0*c/total:6.3f}%  {c:6d}  {sym.strip()}")
