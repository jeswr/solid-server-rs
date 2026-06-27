# AUTHORED-BY Claude Opus 4.8
# Categorize solid-server-rs SELF time into CRYPTO (aws-lc / ecp_nistz / sha / ecdsa) vs RDF
# (oxttl/oxrdf/oxjsonld/serialize/parse) vs ALLOC (alloc/dealloc/malloc/free stub) vs OUR-LOGIC
# (solid_server_rs::*) vs OTHER, by symbolicating EVERY our-code frame (not just the top N).
import gzip, json, sys, subprocess
from collections import Counter

path = sys.argv[1]
binpath = sys.argv[2] if len(sys.argv) > 2 else 'target/release/solid-server-rs'
d = json.load(gzip.open(path))
libs = d['libs']
TEXT = 0x100000000

addr_count = Counter()
total = 0
our_total = 0
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
        if a is None or a < 0: continue
        addr_count[a] += 1
        our_total += 1

items = addr_count.most_common()  # all
full = [hex(TEXT + a) for a, _ in items]
# atos in chunks (cmdline length)
syms = []
for i in range(0, len(full), 500):
    out = subprocess.run(['atos', '-o', binpath, '-arch', 'arm64', '-l', '0x100000000'] + full[i:i+500],
                         capture_output=True, text=True).stdout.splitlines()
    syms.extend(out)

cats = Counter()
catname = Counter()  # category -> representative top function counts
detail = {}
def classify(sym):
    s = sym.lower()
    if any(k in s for k in ['ecp_nistz', 'aws_lc', 'beeu_', 'ecdsa', 'p256', 'nistz256', 'sha256', 'sha512', 'sha2', '_sha', 'bn_', 'gcm', 'aes', 'curve25519', 'ed25519', 'ring_', 'fiat_', 'montgomery']):
        return 'CRYPTO'
    if any(k in s for k in ['oxttl', 'oxrdf', 'oxjsonld', 'oxiri', 'serialize_triples', 'parse_to_triples', 'turtle', 'rdf', 'n3::', 'json_ld']):
        return 'RDF'
    if any(k in s for k in ['dyld-stub$$free', 'dyld-stub$$malloc', '__rust_alloc', '__rust_dealloc', 'alloc::', 'free + ', 'malloc']):
        return 'ALLOC'
    if 'solid_server_rs' in s:
        return 'OUR-LOGIC'
    if any(k in s for k in ['rustls', 'aws_lc_rs', 'tls']):
        return 'TLS-OTHER'
    if any(k in s for k in ['hyper', 'h2::', 'http::', 'httparse', 'tokio', 'mio::', 'axum']):
        return 'HTTP-RUNTIME'
    return 'OTHER'

for (a, c), sym in zip(items, syms):
    cat = classify(sym)
    cats[cat] += c
    key = (cat, sym.split(' (in ')[0].strip())
    detail[key] = detail.get(key, 0) + c

print(f"# {path}")
print(f"# total_samples(all)={total}  our-code_samples={our_total} ({100.0*our_total/total:.1f}% of all)\n")
print("=== our-code SELF time by CATEGORY (% of ALL samples / % of our-code) ===")
for cat, c in cats.most_common():
    print(f"  {cat:14s} {100.0*c/total:6.2f}% of all   {100.0*c/our_total:6.2f}% of our-code   ({c})")

print("\n=== top OUR-LOGIC (non-crypto, non-rdf, non-alloc) functions ===")
our_logic = sorted([(k[1], v) for k, v in detail.items() if k[0] in ('OUR-LOGIC','RDF','ALLOC','OTHER','HTTP-RUNTIME','TLS-OTHER')], key=lambda x: -x[1])
for name, c in our_logic[:25]:
    nm = name if len(name) <= 78 else name[:75]+'...'
    print(f"  {100.0*c/total:6.3f}% of all  {c:6d}  {nm}")
