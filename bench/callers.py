# AUTHORED-BY Claude Opus 4.8
# For a given hot leaf reladdr in a lib, show the top CALLER frames (the parent in the stack), to
# tell a syscall-park (kevent/poll under the tokio reactor) apart from a productive recv/send.
import gzip, json, sys, subprocess
from collections import Counter

path = sys.argv[1]
leaf_lib = sys.argv[2]
leaf_addr = int(sys.argv[3], 16)
d = json.load(gzip.open(path))
libs = d['libs']
TEXT = 0x100000000

caller_count = Counter()  # (libname, reladdr) -> count
total_leaf = 0
for t in d['threads']:
    funcs = t['funcTable']; func_res = funcs['resource']
    frames = t['frameTable']; frame_func = frames['func']; frame_addr = frames['address']
    stacks = t['stackTable']; stack_frame = stacks['frame']; stack_prefix = stacks['prefix']
    res = t['resourceTable']; res_lib = res['lib']
    def libof(fn):
        r = func_res[fn]
        if r is None or r < 0: return None
        li = res_lib[r]
        if li is None or li < 0 or li >= len(libs): return None
        return libs[li]['name']
    for s in t['samples']['stack']:
        if s is None: continue
        fr = stack_frame[s]; fn = frame_func[fr]
        if libof(fn) != leaf_lib or frame_addr[fr] != leaf_addr: continue
        total_leaf += 1
        p = stack_prefix[s]
        if p is None:
            caller_count[('(root)', 0)] += 1
            continue
        pfr = stack_frame[p]; pfn = frame_func[pfr]
        caller_count[(libof(pfn), frame_addr[pfr])] += 1

print(f"# leaf {leaf_lib} 0x{leaf_addr:x} appeared as leaf in {total_leaf} samples; top callers:")
items = caller_count.most_common(12)
# symbolicate our-binary callers
for (ln, a), c in items:
    sym = ''
    if ln == 'solid-server-rs':
        sym = subprocess.run(['atos','-o','target/release/solid-server-rs','-arch','arm64','-l','0x100000000', hex(TEXT+a)],
                             capture_output=True, text=True).stdout.strip()
    print(f"  {100.0*c/total_leaf:6.2f}%  {c:6d}  [{ln}] 0x{a:x}  {sym}")
