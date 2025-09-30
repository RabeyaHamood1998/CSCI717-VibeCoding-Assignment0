#!/usr/bin/env python3
"""
auto_solve_hardcoded.py

Self-contained Aristocrat solver that:
- Has a hardcoded ciphertext (edit CIPHERTEXT at top).
- Uses embedded quadgrams + a small wordlist to score candidates.
- Uses frequency-seed + simulated annealing + local pairwise refinement.
- Prints final plaintext candidate and cipher->plain mapping.

Tweak RESTARTS / ITERS / POLISH_ITERS at top if needed.
"""

import random, math, re
from collections import Counter

# -----------------------
# Hardcoded ciphertext (edit if needed)
# -----------------------
CIPHERTEXT = (
    "FZQ YQOFQUF OQEKQF UE YUVKVY UYFQBBUVQYFBI HUFZ EUCIBUAUFB. "
    "FZQ FWEQ HZE YQFTQY FZQGBQBTQB HUFZ FZUB UYFQBBUVQYTQ "
    "ZWTTQ YTWQB HZWF FZQ FWEQ HZE YQTQWBQB."
)

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_LO = ALPH.lower()

# -----------------------
# Tunable parameters
# -----------------------
RESTRTS = 220        # number of random-restart SA runs
ITERS = 8000         # iterations per restart
START_TEMP = 1.2
COOLING = 0.9995

POLISH_ITERS = 20000  # heavier local polish on best candidate
TARGETED_K = 12       # try swaps among top-K ambiguous letters

# -----------------------
# Embedded quadgrams (medium-size high-signal subset)
# (Not the full 30k list, but much stronger than nothing)
# -----------------------
_EMBED_QUADS = {
    "TION":72948,"NTHE":67934,"THER":62744,"THAT":59316,"OFTH":49734,
    "FTHE":48915,"THES":48201,"WITH":43255,"INTH":42856,"ATIO":40539,
    "TAND":39789,"MENT":39234,"IONS":38129,"THIS":37819,"HERE":37025,
    "ETHE":31000,"FROM":30000,"EVER":29500,"OVER":28500,"COMP":27500,
    "NESS":26000,"ENCE":25500,"RETH":25000,"AND ":20000,"THEM":20000,
    "WHIC":19500,"THAN":19000,"ING ":18500,"HAVE":18000,"THEC":17500,
    "TAIN":17000,"ATIO":16500,"THER":16000,"ERE ":15500,"WITI":15000
    # this is deliberately modest — extend if you want more accuracy
}
_TOTAL = sum(_EMBED_QUADS.values())
_QUAD_LOGP = {q: math.log10(c/_TOTAL) for q,c in _EMBED_QUADS.items()}
_FLOOR = math.log10(0.01/_TOTAL)

def quadgram_score(text: str) -> float:
    s = re.sub(r'[^A-Z]','', text.upper())
    sc = 0.0
    for i in range(len(s)-3):
        sc += _QUAD_LOGP.get(s[i:i+4], _FLOOR)
    return sc

# -----------------------
# Small dictionary for word-match scoring (common words)
# -----------------------
_WORDS = set("""
the be to of and a in that have it for not on with he as you do at this but his by
from they we say her she or an will my one all would there their what so up out if
about who get which go me when make can like time no just him know take people into
year your good some could them see other than then now look only come its over think
also back after use two how our work first well way even new want because any these give
day most us sample aristocrat cipher text students frequency analysis pattern matching methods
""".split())

def word_score(plain: str) -> float:
    words = [w for w in re.sub(r'[^a-z ]','', plain.lower()).split() if w]
    if not words:
        return -50.0
    matches = sum(1 for w in words if w in _WORDS or (len(w)==1 and w in ('a','i')))
    return 10.0 * (matches / len(words))

# -----------------------
# Combined scoring function
# -----------------------
def combined_score(plain: str) -> float:
    # weights chosen so quadgrams matter but word hits can steer small text
    q = quadgram_score(plain)
    w = word_score(plain)
    return q * 1.0 + w * 3.0

# -----------------------
# Cipher utilities
# -----------------------
def decrypt_with_key(cipher: str, keystr: str) -> str:
    table = str.maketrans(ALPH, keystr.upper())
    return cipher.upper().translate(table).lower()

def key_from_map(mapping: dict) -> str:
    # mapping: cipher-letter -> plain-letter (both uppercase)
    return ''.join(mapping.get(ch, '?') for ch in ALPH)

def frequency_seed_key(cipher: str) -> str:
    # map most frequent cipher letters to ETAOIN... order
    ETA = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    letters = [c for c in cipher.upper() if c.isalpha()]
    cnt = Counter(letters).most_common()
    freq_order = [p for p,_ in cnt]
    for ch in ALPH:
        if ch not in freq_order:
            freq_order.append(ch)
    mapping = {c:p for c,p in zip(freq_order, ETA)}
    # produce keystring: position for cipher 'A'..'Z' -> plaintext letter
    return ''.join(mapping.get(ch, random.choice(ALPH)) for ch in ALPH)

def swap_keystr(keystr: str, i:int, j:int) -> str:
    lst = list(keystr)
    lst[i], lst[j] = lst[j], lst[i]
    return ''.join(lst)

# -----------------------
# Simulated annealing single run (start from freq seed)
# -----------------------
def sa_single(cipher: str, iters: int, start_temp: float, cooling: float, seed=None):
    if seed is not None:
        random.seed(seed)
    key = frequency_seed_key(cipher)
    # small randomization
    for _ in range(8):
        a,b = random.sample(range(26),2)
        key = swap_keystr(key,a,b)
    plain = decrypt_with_key(cipher, key)
    score = combined_score(plain)

    best_local = (score, key, plain)
    temp = start_temp

    for _ in range(iters):
        a,b = random.sample(range(26),2)
        cand = swap_keystr(key,a,b)
        cand_plain = decrypt_with_key(cipher, cand)
        cand_score = combined_score(cand_plain)
        if cand_score > score or random.random() < math.exp((cand_score-score)/max(1e-12,temp)):
            key = cand
            plain = cand_plain
            score = cand_score
            if score > best_local[0]:
                best_local = (score, key, plain)
        temp *= cooling
    return best_local  # (score,key,plain)

# -----------------------
# Local exhaustive pairwise refinement (until no improvement)
# -----------------------
def exhaustive_refine(cipher: str, start_key: str, start_score: float):
    best_score = start_score
    best_key = start_key
    best_plain = decrypt_with_key(cipher, best_key)
    improved = True
    while improved:
        improved = False
        # try all 325 swaps
        for i in range(26):
            for j in range(i+1,26):
                cand = swap_keystr(best_key, i, j)
                cand_plain = decrypt_with_key(cipher, cand)
                cand_score = combined_score(cand_plain)
                if cand_score > best_score:
                    best_score = cand_score
                    best_key = cand
                    best_plain = cand_plain
                    improved = True
        # repeat until no swap improves
    return best_score, best_key, best_plain

# -----------------------
# Targeted swap among ambiguous letters (k^2 small try)
# -----------------------
def targeted_swaps(cipher: str, key: str, k=TARGETED_K):
    plain = decrypt_with_key(cipher, key)
    counts = Counter(ch for ch in plain if ch.isalpha())
    # mapped cipher->plain
    mapped = {ALPH[i]: key[i].upper() for i in range(26)}
    # ambiguous: cipher letters whose mapped plain has low frequency in candidate
    metrics = [(counts.get(mapped[c].lower(),0), c) for c in ALPH]
    metrics.sort()  # low frequency first
    candidates = [c for _,c in metrics[:k]]
    best = (combined_score(plain), key, plain)
    for i in range(len(candidates)):
        for j in range(i+1, len(candidates)):
            a,b = candidates[i], candidates[j]
            ia, ib = ord(a)-65, ord(b)-65
            cand = swap_keystr(key, ia, ib)
            cand_plain = decrypt_with_key(cipher, cand)
            sc = combined_score(cand_plain)
            if sc > best[0]:
                best = (sc, cand, cand_plain)
    return best  # (score,key,plain)

# -----------------------
# Orchestrator
# -----------------------
def solve_hardcoded(cipher: str, restarts=RESTRTS, iters=ITERS,
                    start_temp=START_TEMP, cooling=COOLING):
    best_global = (-1e99, None, None)
    for r in range(restarts):
        seed = random.randrange(1<<30)
        sc, k, p = sa_single(cipher, iters, start_temp, cooling, seed=seed)
        if sc > best_global[0]:
            best_global = (sc, k, p)
            print(f"[Restart {r+1}/{restarts}] new best score {sc:.3f} -> {p[:120]}")
    print("[*] Exhaustive local refinement (pairwise)...")
    sc2, k2, p2 = exhaustive_refine(cipher, best_global[1], best_global[0])
    if sc2 > best_global[0]:
        best_global = (sc2, k2, p2)
        print(f"[+] refinement improved to {sc2:.3f}")
    # targeted swaps
    print("[*] Targeted small-swap search...")
    tsc, tk, tp = targeted_swaps(cipher, best_global[1], k=TARGETED_K)
    if tsc > best_global[0]:
        best_global = (tsc, tk, tp)
        print(f"[+] targeted swaps improved to {tsc:.3f}")

    # final polish (optional heavier SA starting from best)
    print("[*] Final polish (short SA)...")
    s2,k3,p3 = sa_single(cipher, int(POLISH_ITERS/4), start_temp=1.0, cooling=0.9996, seed=random.randrange(1<<30))
    # only accept if better
    if combined_score(p3) > best_global[0]:
        best_global = (combined_score(p3), k3, p3)

    return best_global  # (score, key, plain)

# -----------------------
# Output mapping nicely
# -----------------------
def print_mapping(keystr: str):
    print("\nMapping (cipher -> plain):")
    for i,ch in enumerate(ALPH):
        print(f" {ch} -> {keystr[i].upper()}", end="  ")
        if (i+1)%6==0:
            print()
    print()

# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    random.seed()  # remove or set a number for deterministic debugging
    print("[*] Ciphertext (hardcoded):")
    print(CIPHERTEXT, "\n")
    score, key, plain = solve_hardcoded(CIPHERTEXT, restarts=RESTRTS, iters=ITERS)
    print("\n" + "="*72)
    print(f"FINAL BEST SCORE: {score:.6f}\n")
    print("Plaintext candidate:\n")
    print(plain)
    print_mapping(key)
    # If you want the keystring to hardcode later:
    print("\nKey string (A->Z mapping):", key)
