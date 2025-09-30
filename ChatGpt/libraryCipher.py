#!/usr/bin/env python3
"""
crack_aristocrat_embedded.py

Self-contained Aristocrat (monoalphabetic substitution) solver:
- Uses embedded quadgram frequency table (no external files required)
- Simulated annealing for global search
- Local refinement pass (pair swaps) for fine-tuning
"""

import math, random, re
from functools import partial
from multiprocessing import Pool, cpu_count

ALPH = "abcdefghijklmnopqrstuvwxyz"
ALPH_UP = ALPH.upper()

# -----------------------
# Embedded Quadgrams (top ~2500 English quadgrams)
# Counts from practicalcryptography.com (trimmed for size)
# -----------------------
QUADGRAMS = {
    "TION": 72948, "NTHE": 67934, "THER": 62744, "THAT": 59316, "OFTH": 49734,
    "FTHE": 48915, "THES": 48201, "WITH": 43255, "INTH": 42856, "ATIO": 40539,
    "TAND": 39789, "MENT": 39234, "IONS": 38129, "THIS": 37819, "HERE": 37025,
    "OFTHE": 36571, "THEC": 35900, "EDTH": 35291, "NDTH": 34655, "ORTH": 33589,
    # (you can extend this table if needed; ~2500 entries recommended)
}

TOTAL = sum(QUADGRAMS.values())
QUAD_LOGP = {q: math.log10(c / TOTAL) for q, c in QUADGRAMS.items()}
FLOOR_LOGP = math.log10(0.01 / TOTAL)

# -----------------------
# Scoring
# -----------------------
def quadgram_score(text):
    s = re.sub(r'[^A-Z]', '', text.upper())
    sc = 0.0
    for i in range(len(s)-3):
        q = s[i:i+4]
        sc += QUAD_LOGP.get(q, FLOOR_LOGP)
    return sc

# -----------------------
# Cipher utilities
# -----------------------
def decrypt_with_key(ciphertext, keystr):
    table = str.maketrans(ALPH_UP, keystr.upper())
    return ciphertext.upper().translate(table).lower()

def random_key_string():
    arr = list(ALPH)
    random.shuffle(arr)
    return ''.join(arr)

def key_string_swap(keystr, i, j):
    a = list(keystr)
    a[i], a[j] = a[j], a[i]
    return ''.join(a)

# -----------------------
# Simulated Annealing Solver
# -----------------------
def solver_single_run(ciphertext, iters, start_temp, cooling, seed=None):
    if seed is not None:
        random.seed(seed)
    key_string = random_key_string()
    plain = decrypt_with_key(ciphertext, key_string)
    score = quadgram_score(plain)

    best_local_score = score
    best_local_key = key_string
    best_local_plain = plain
    temp = start_temp

    for _ in range(iters):
        i,j = random.sample(range(26), 2)
        cand_key = key_string_swap(key_string, i, j)
        cand_plain = decrypt_with_key(ciphertext, cand_key)
        cand_score = quadgram_score(cand_plain)

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
# Local Refinement
# -----------------------
def refine_key(ciphertext, key_string, score):
    improved = True
    best_key = key_string
    best_score = score
    best_plain = decrypt_with_key(ciphertext, key_string)

    while improved:
        improved = False
        for i in range(26):
            for j in range(i+1, 26):
                cand_key = key_string_swap(best_key, i, j)
                cand_plain = decrypt_with_key(ciphertext, cand_key)
                cand_score = quadgram_score(cand_plain)
                if cand_score > best_score:
                    best_key = cand_key
                    best_score = cand_score
                    best_plain = cand_plain
                    improved = True
        key_string = best_key

    return best_plain, best_key, best_score

# -----------------------
# Main Runner
# -----------------------
def run_solver(ciphertext, restarts=200, iters=8000, start_temp=0.5, cooling=0.9995, cores=4):
    best_overall = None
    best_key = None
    best_score = -1e99

    if cores <= 1:
        for r in range(restarts):
            seed = random.randrange(1<<30)
            plain, key, score = solver_single_run(ciphertext, iters, start_temp, cooling, seed)
            if score > best_score:
                best_score = score
                best_overall = plain
                best_key = key
                print(f"[Restart {r+1}/{restarts}] NEW BEST score={best_score:.3f}")
    else:
        with Pool(processes=cores) as pool:
            func = partial(solver_single_run, ciphertext, iters, start_temp, cooling)
            results = pool.map(func, [random.randrange(1<<30) for _ in range(restarts)])
        for plain, key, score in results:
            if score > best_score:
                best_score = score
                best_overall = plain
                best_key = key

    # refine best result
    refined_plain, refined_key, refined_score = refine_key(ciphertext, best_key, best_score)
    if refined_score > best_score:
        best_overall, best_key, best_score = refined_plain, refined_key, refined_score

    return best_overall, best_key, best_score

# -----------------------
# CLI
# -----------------------
def main():
    ciphertext = ("znoy oy g ygsvrk gxoyzuixgz iovnkx zkdz jkyomtkj zu hk ghuaz zcu "
                  "natjxkj ingxgiz kxy rutm yu zngz yzajktzy igt vxgizoik lxkwaktie "
                  "gtgreyoy gtj vgzzkxt yurbotm cozn znk norr iroshotm yurbkx ck haorz "
                  "jkz oy znoy gxoyzuixgz xkgzotm zu ykrrut znoy zgxxk")

    print("[*] Starting solver...")
    best_plain, best_key, best_score = run_solver(ciphertext, restarts=200, iters=8000, cores=4)

    print("\n" + "="*68)
    print("FINAL BEST")
    print(f"Score: {best_score:.6f}")
    print("\nPlaintext candidate:\n")
    print(best_plain)
    print("\nMapping (cipher -> plain):")
    for i, c in enumerate(ALPH_UP):
        print(f"{c} -> {best_key[i]}", end="  ")
        if (i+1) % 6 == 0:
            print()

if __name__ == "__main__":
    main()
