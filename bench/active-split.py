# AUTHORED-BY Claude Opus 4.8
# Compute the ACTIVE-CPU distribution by EXCLUDING idle-park samples (tokio worker park via
# pthread_cond_wait, and the mio/kqueue reactor blocking wait), so the remaining percentages
# reflect where real on-CPU work goes. A sample is PARK if its leaf is one of the known wait
# syscalls reached via pthread cond-wait or mio::poll. Everything else is ACTIVE; ACTIVE samples
# are then split CRYPTO / NET-SYSCALL / MALLOC / PARSE-HTTP-JSON / OUR-LOGIC / PROFILER / OTHER.
import gzip, json, sys, subprocess
from collections import Counter

path = sys.argv[1]
d = json.load(gzip.open(path))
libs = d['libs']
TEXT = 0x100000000

# Known idle-park kernel leaf reladdrs (validated via callers.py):
#  0x450c <- pthread_cond_wait (worker park);  0x6fc4 <- mio::poll (reactor wait);  0x39dc <- pthread
PARK_KERNEL = {0x450c, 0x6fc4, 0x39dc}
# samply's own sample-writer (File::write_vectored) — profiler overhead, exclude from ACTIVE too.
PROFILER_KERNEL = {0x4b8c}

# cache atos lookups for our-binary addrs
_sym_cache = {}
def our_sym(a):
    if a in _sym_cache: return _sym_cache[a]
    s = subprocess.run(['atos','-o','target/release/solid-server-rs','-arch','arm64','-l','0x100000000', hex(TEXT+a)],
                       capture_output=True, text=True).stdout.strip()
    _sym_cache[a] = s
    return s

# collect leaf (lib, reladdr) -> count
leaf = Counter()
total = 0
for t in d['threads']:
    funcs = t['funcTable']; func_res = funcs['resource']
    frames = t['frameTable']; frame_func = frames['func']; frame_addr = frames['address']
    stacks = t['stackTable']; stack_frame = stacks['frame']
    res = t['resourceTable']; res_lib = res['lib']
    def libof(fn):
        r = func_res[fn]
        if r is None or r < 0: return None
        li = res_lib[r]
        if li is None or li < 0 or li >= len(libs): return None
        return libs[li]['name']
    for s in t['samples']['stack']:
        if s is None: continue
        total += 1
        fr = stack_frame[s]; fn = frame_func[fr]
        leaf[(libof(fn), frame_addr[fr])] += 1

park = sum(c for (ln,a),c in leaf.items() if ln=='libsystem_kernel.dylib' and a in PARK_KERNEL)
prof = sum(c for (ln,a),c in leaf.items() if ln=='libsystem_kernel.dylib' and a in PROFILER_KERNEL)
active = total - park - prof

def classify(ln, a):
    if ln == 'solid-server-rs':
        s = our_sym(a).lower()
        if any(k in s for k in ['ecp_nistz','aws_lc','beeu_','ecdsa','nistz256','sha256','sha512','bn_','fiat_']):
            return 'CRYPTO'
        if any(k in s for k in ['tcpstream','net..tcp','::read','write_vectored','net..tcp..tcpstream']):
            return 'NET-SYSCALL(rust)'
        if any(k in s for k in ['base64','serde_json','from_utf8','httparse','hyper..proto','url::parser','memchr','::write_str','fmt::write','fmt::format']):
            return 'PARSE/HTTP/JSON'
        if any(k in s for k in ['rust_alloc','rust_dealloc','dyld-stub$$free','dyld-stub$$malloc','alloc::','rdl_alloc','rdl_dealloc']):
            return 'MALLOC'
        if 'solid_server_rs' in s or 'solid_oidc_verifier' in s:
            return 'OUR-LOGIC'
        if any(k in s for k in ['oxttl','oxrdf','oxiri','oxjsonld']):
            return 'RDF'
        if any(k in s for k in ['tokio','mio::','axum','h2::']):
            return 'RUNTIME'
        return 'OUR-OTHER'
    if ln == 'libsystem_malloc.dylib': return 'MALLOC(sys)'
    if ln == 'libsystem_kernel.dylib': return 'NET-SYSCALL(kernel)'
    if ln == 'libsystem_platform.dylib': return 'MEMCPY/PLATFORM'
    if ln == 'libsystem_pthread.dylib': return 'PTHREAD'
    if ln == 'libsystem_c.dylib': return 'LIBC'
    return f'OTHER({ln})'

cats = Counter()
for (ln,a),c in leaf.items():
    if ln=='libsystem_kernel.dylib' and (a in PARK_KERNEL or a in PROFILER_KERNEL):
        continue
    cats[classify(ln,a)] += c

print(f"# {path}")
print(f"# total={total}  PARK(idle)={park} ({100.0*park/total:.1f}%)  PROFILER-WRITE={prof} ({100.0*prof/total:.1f}%)  ACTIVE={active} ({100.0*active/total:.1f}%)\n")
print("=== ACTIVE-CPU distribution (% of ACTIVE, i.e. park+profiler excluded) ===")
for cat,c in cats.most_common():
    print(f"  {cat:22s} {100.0*c/active:6.2f}%   ({c})")
