#!/usr/bin/env python3
"""
crack_aristocrat_improved.py

Improved monoalphabetic (Aristocrat) solver:
- Uses quadgram scoring (preferred) if english_quadgrams.txt is present.
- Falls back to combined word/ngram/letter-freq scoring if quadgrams not available.
- Simulated annealing acceptance to escape local optima.
- Optional multiprocessing to run restarts in parallel.

Usage examples:
    python3 crack_aristocrat_improved.py -f ciphertext.txt --restarts 200 --iters 8000 --cores 4
    echo "cipher text ..." | python3 crack_aristocrat_improved.py

Place 'english_quadgrams.txt' (quadgram counts) next to the script to enable the quadgram scorer.
"""

from collections import Counter
import math, random, re, sys, argparse, os
from functools import partial
from multiprocessing import Pool, cpu_count

ALPH = "abcdefghijklmnopqrstuvwxyz"
ALPH_UP = ALPH.upper()

# -----------------------
# Default solver params
# -----------------------
DEFAULT_RESTARTS = 250
DEFAULT_ITERS =  8000
DEFAULT_START_TEMP = 0.8
DEFAULT_COOLING = 0.9996
DEFAULT_CORES = 8

# -----------------------
# Small fallback wordlist and ngrams (used if no quadgrams)
# -----------------------
COMMON_WORDS = set("""
the be to of and a in that have it for not on with he as you do at
this but his by from they we say her she or an will my one all would there their
what so up out if about who get which go me when make can like time no just him know take
""".split())

COMMON_NGRAMS = {
    "th": 2.0, "he": 2.0, "in": 1.5, "er": 1.2, "an": 1.2, "re": 1.0,
    "on": 1.0, "at": 0.9, "en": 0.9, "nd": 0.9, "ti": 0.8, "es": 0.8,
    "or": 0.7, "te": 0.7, "of": 0.7, "ing": 1.8, "ent": 1.2, "ion": 1.2,
    "and": 1.5, "ere": 1.0
}

ENGLISH_LETTER_FREQ = {
 'a': 8.167,'b':1.492,'c':2.782,'d':4.253,'e':12.702,'f':2.228,'g':2.015,
 'h':6.094,'i':6.966,'j':0.153,'k':0.772,'l':4.025,'m':2.406,'n':6.749,
 'o':7.507,'p':1.929,'q':0.095,'r':5.987,'s':6.327,'t':9.056,'u':2.758,
 'v':0.978,'w':2.360,'x':0.150,'y':1.974,'z':0.074
}



# -----------------------
# Quadgram loader
# -----------------------
def load_quadgrams(path="english_quadgrams.txt"):
    """Load quadgram counts file, or fallback to embedded dictionary."""
    d = {}
    total = 0
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    quad = parts[0].upper()
                    try:
                        cnt = int(parts[1])
                    except:
                        continue
                    if len(quad) == 4:
                        d[quad] = d.get(quad, 0) + cnt
                        total += cnt
    else:
        print("[*] english_quadgrams.txt not found: using embedded quadgrams.")
        d = dict(EMBEDDED_QUADGRAMS)
        total = sum(d.values())

    if total == 0:
        return None, None
    logp = {q: math.log10(c/total) for q, c in d.items()}
    floor = math.log10(0.01/total)
    return logp, floor

# -----------------------
# Scoring functions
# -----------------------
def quadgram_score(text, quad_logp, floor_logp):
    s = re.sub(r'[^A-Z]', '', text.upper())
    sc = 0.0
    for i in range(len(s)-3):
        q = s[i:i+4]
        sc += quad_logp.get(q, floor_logp)
    return sc

def score_word_match(plain: str, wordset: set) -> float:
    words = [w for w in re.sub(r'[^a-z ]', '', plain.lower()).split() if len(w)>0]
    if not words: return -100.0
    matches = sum(1 for w in words if w in wordset or (len(w)==1 and w in ("a","i")))
    return 10.0 * (matches/len(words))

def score_ngram(plain: str) -> float:
    s = re.sub(r'[^a-z]', '', plain.lower())
    total = 0.0
    for ngram, w in COMMON_NGRAMS.items():
        total += s.count(ngram) * w
    return total

def score_letter_freq(plain: str) -> float:
    s = re.sub(r'[^a-z]', '', plain.lower())
    N = len(s)
    if N == 0: return -100.0
    counts = Counter(s)
    chi = 0.0
    for ch, ef in ENGLISH_LETTER_FREQ.items():
        obs = counts.get(ch, 0)
        exp = ef * N / 100.0
        if exp>0:
            chi += ((obs - exp)**2) / exp
    return -chi / 100.0

def combined_score_plain(plain: str, wordset:set):
    """Fallback score combining word match, ngram and letter freq."""
    return score_word_match(plain, wordset) * 1.0 + score_ngram(plain) * 0.7 + score_letter_freq(plain) * 0.5

# -----------------------
# Cipher utilities
# -----------------------
def apply_key(ciphertext: str, key_map: dict) -> str:
    out = []
    for ch in ciphertext:
        if ch.isalpha():
            low = ch.lower()
            p = key_map.get(low)
            out.append(p if p else '?')
        else:
            out.append(ch)
    return "".join(out)

def key_to_map(key_string: str) -> dict:
    """key_string is 26-letter mapping for ciphertext alphabet a..z -> plaintext letter"""
    return {ALPH[i]: key_string[i] for i in range(26)}

def map_to_key(mapping: dict) -> str:
    """Inverse: produce 26-char key string from cipher->plain dict"""
    return ''.join(mapping.get(ch, '?') for ch in ALPH)

def frequency_seed(ciphertext: str):
    s = [ch for ch in ciphertext.lower() if ch.isalpha()]
    cnt = Counter(s)
    freq_sorted = [p for p,_ in cnt.most_common()]
    for ch in ALPH:
        if ch not in freq_sorted:
            freq_sorted.append(ch)
    mapping = {}
    ETAOIN = "etaoinshrdlcumwfgypbvkjxqz"
    for c, p in zip(freq_sorted, ETAOIN):
        mapping[c] = p
    return mapping

def random_key_string():
    arr = list(ALPH)
    random.shuffle(arr)
    return ''.join(arr)

def key_string_swap(keystr, i, j):
    a = list(keystr)
    a[i], a[j] = a[j], a[i]
    return ''.join(a)

# -----------------------
# Single-restart solver (used in parallel)
# -----------------------
def solver_single_run(ciphertext, quad_logp, floor_logp, wordset,
                      iters, start_temp, cooling, seed=None):
    if seed is not None:
        random.seed(seed)
    # Key representation: key_string such that position 0 = plaintext letter for 'a' (i.e., cipher 'a'->key[0])
    # Start from frequency seed -> convert to key string (mapping cipher->plain)
    freq_map = frequency_seed(ciphertext)
    key_list = [freq_map.get(ch, random.choice(ALPH)) for ch in ALPH]
    key_string = ''.join(key_list)
    # randomize a little
    for _ in range(8):
        i,j = random.sample(range(26),2)
        key_string = key_string_swap(key_string, i, j)

    plain = decrypt_with_key(ciphertext, key_string)
    if quad_logp:
        score = quadgram_score(plain, quad_logp, floor_logp)
    else:
        score = combined_score_plain(plain, wordset)

    best_local_score = score
    best_local_key = key_string
    best_local_plain = plain
    temp = start_temp

    for it in range(iters):
        i,j = random.sample(range(26), 2)
        cand_key = key_string_swap(key_string, i, j)
        cand_plain = decrypt_with_key(ciphertext, cand_key)
        if quad_logp:
            cand_score = quadgram_score(cand_plain, quad_logp, floor_logp)
        else:
            cand_score = combined_score_plain(cand_plain, wordset)

        # acceptance: if better or with prob depending on temp (sa)
        if cand_score > score or random.random() < math.exp((cand_score - score) / max(1e-12, temp)):
            key_string = cand_key
            plain = cand_plain
            score = cand_score
            if score > best_local_score:
                best_local_score = score
                best_local_key = key_string
                best_local_plain = plain

        temp *= cooling

    return best_local_plain, best_local_key, best_local_score

# -----------------------
# Decrypt helper
# -----------------------
def decrypt_with_key(ciphertext, keymap_str):
    table = str.maketrans(ALPH_UP, keymap_str.upper())
    return ciphertext.upper().translate(table).lower()

# -----------------------
# Parallel runner
# -----------------------
def run_solver(ciphertext, quad_logp, floor_logp, wordset,
               restarts, iters, start_temp, cooling, cores):
    best_overall = None
    best_key = None
    best_score = -1e99

    if cores <= 1:
        # sequential
        for r in range(restarts):
            seed = random.randrange(1<<30)
            plain, key, score = solver_single_run(ciphertext, quad_logp, floor_logp, wordset,
                                                  iters, start_temp, cooling, seed)
            if score > best_score:
                best_score = score
                best_overall = plain
                best_key = key
                print(f"[Restart {r+1}/{restarts}] NEW BEST score={best_score:.3f} -> {best_overall[:120]}")
    else:
        # parallel: partition restarts across processes
        seeds = [random.randrange(1<<30) for _ in range(restarts)]
        with Pool(processes=cores) as pool:
            func = partial(solver_single_run, ciphertext, quad_logp, floor_logp, wordset, iters, start_temp, cooling)
            results = pool.map(func, seeds)
        # gather
        for idx, (plain, key, score) in enumerate(results):
            if score > best_score:
                best_score = score
                best_overall = plain
                best_key = key
                print(f"[Parallel restart {idx+1}/{restarts}] NEW BEST score={best_score:.3f} -> {best_overall[:120]}")

    return best_overall, best_key, best_score

# -----------------------
# CLI + main
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Improved Aristocrat solver (quadgrams + SA + parallel restarts)")
    p.add_argument("-f", "--file", help="ciphertext file (default: sample or stdin)")
    p.add_argument("-w", "--wordlist", help="optional wordlist file (one word per line) to improve scoring")
    p.add_argument("-r", "--restarts", type=int, default=DEFAULT_RESTARTS)
    p.add_argument("-i", "--iters", type=int, default=DEFAULT_ITERS)
    p.add_argument("-t", "--temp", type=float, default=DEFAULT_START_TEMP)
    p.add_argument("-c", "--cooling", type=float, default=DEFAULT_COOLING)
    p.add_argument("--cores", type=int, default=DEFAULT_CORES, help="number of parallel processes (default 1)")
    return p.parse_args()

def load_wordlist(path):
    words = set(COMMON_WORDS)
    if not path:
        return words
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                w = ln.strip().lower()
                if w:
                    words.add(w)
        print(f"[+] Loaded {len(words)} words from {path}")
    except Exception as e:
        print(f"[!] Could not load wordlist {path}: {e}. Using built-in small list.")
    return words

def main():
    args = parse_args()

    # read ciphertext
    if args.file:
        if not os.path.exists(args.file):
            print(f"[!] File {args.file} not found.")
            return
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            ciphertext = f.read()
    else:
        if not sys.stdin.isatty():
            ciphertext = sys.stdin.read()
        else:
            # small sample default
            ciphertext = ("znoy oy g ygsvrk gxoyzuixgz iovnkx zkdz jkyomtkj zu hk ghuaz zcu natjxkj ingxgiz kxy rutm yu zngz yzajktzy igt vxgizoik lxkwaktie gtgreyoy gtj vgzzkxt yurbotm cozn znk norr iroshotm yurbkx ck haorz jkz oy znoy gxoyzuixgz xkgzotm zu ykrrut znoy zgxxk")

    ciphertext = re.sub(r'\s+', ' ', ciphertext.strip())

    # load quadgrams if present
    quad_logp, floor_logp = load_quadgrams()
    if quad_logp:
        print("[+] Loaded english_quadgrams.txt: using quadgram scorer (best).")
    else:
        print("[*] english_quadgrams.txt not found: using fallback combined scorer (word/ngram/freq).")

    wordset = load_wordlist(args.wordlist)

    cores = args.cores if args.cores > 0 else 1
    if cores > cpu_count():
        cores = cpu_count()

    print(f"[*] Starting solver: restarts={args.restarts}, iters={args.iters}, cores={cores}")
    best_plain, best_key, best_score = run_solver(ciphertext, quad_logp, floor_logp,
                                                  wordset, args.restarts, args.iters, args.temp, args.cooling, cores)

    print("\n" + "="*68)
    print("FINAL BEST")
    print(f"Score: {best_score:.6f}")
    if best_key is None:
        print("[!] No key found.")
        return
    print("\nPlaintext candidate:\n")
    # produce readable mapping on ciphertext preserving non-letters
    table = str.maketrans(ALPH_UP, best_key.upper())
    mapped = ciphertext.upper().translate(table)
    print(mapped)
    print("\nMapping (cipher -> plain):")
    for i, c in enumerate(ALPH_UP):
        print(f" {c} -> {best_key[i]}", end="  ")
        if (i+1) % 6 == 0:
            print()
    print("\nNotes: to get better results, place a full english_quadgrams.txt file next to the script (or increase restarts/iters).")

if __name__ == "__main__":
    main()
