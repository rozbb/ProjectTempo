#!/usr/bin/env python3
import ctypes as C
import os
import time

# ---------------------------------------------------------------------------
# Global configuration
# ---------------------------------------------------------------------------

NUM_ALGOS = 5
NUM_K = 3
NUM_RUNS = 1000

KYBER_N = 256
KYBER_Q = 3329
KYBER_SYMBYTES = 32

PK_SIZES = [800, 1184, 1568]
SK_SIZES = [1632, 2400, 3168]
CT_SIZES = [768, 1088, 1568]
SS_LEN   = 32

algo_names = [
    "Algorithm A0", "Algorithm A1",
    "Algorithm B0", "Algorithm C0", "Algorithm C1",
]

kem_labels_gen = ["MLKEM-512.gen_a", "MLKEM-768.gen_a", "MLKEM-1024.gen_a"]
kem_labels  = ["MLKEM-512", "MLKEM-768", "MLKEM-1024"]
pake_labels = ["NoIC[MLKEM-512]", "NoIC[MLKEM-768]", "NoIC[MLKEM-1024]"]

LIB_PATHS = [
    [f"lib/libnoic_mlkem512_{s}.so"  for s in ["a0", "a1", "b0", "c0", "c1"]],
    [f"lib/libnoic_mlkem768_{s}.so"  for s in ["a0", "a1", "b0", "c0", "c1"]],
    [f"lib/libnoic_mlkem1024_{s}.so" for s in ["a0", "a1", "b0", "c0", "c1"]],
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_seed(n: int) -> bytes:
    return os.urandom(n)


def print_table(row_labels, col_labels, values):
    print("\n%-18s" % "", end="")
    for name in col_labels:
        pad = (14 - len(name)) // 2
        cell = " " * pad + name + " " * (14 - pad - len(name))
        print(" | " + cell, end="")
    print()
    print("-" * (18 + len(col_labels) * (14 + 3)))
    for r, label in enumerate(row_labels):
        print("%-18s" % label, end="")
        for c in range(len(col_labels)):
            print(" | %*.4f ms" % (11, values[r][c]), end="")
        print()
    print()


# ---------------------------------------------------------------------------
# API resolvers
# ---------------------------------------------------------------------------

def resolve_gen_matrix(lib, k_idx: int):
    if k_idx == 0:
        name = "pqcrystals_kyber512_ref_gen_matrix"
    elif k_idx == 1:
        name = "pqcrystals_kyber768_ref_gen_matrix"
    else:
        name = "pqcrystals_kyber1024_ref_gen_matrix"

    fn = getattr(lib, name)
    fn.argtypes = [
        C.POINTER((C.c_int16 * KYBER_N) * 4 * 4),
        C.POINTER(C.c_uint8),
        C.c_int,
    ]
    fn.restype = None
    return fn


def resolve_kyber_api(lib, k_idx: int):
    if k_idx == 0:
        prefix = "pqcrystals_kyber512_ref_"
    elif k_idx == 1:
        prefix = "pqcrystals_kyber768_ref_"
    else:
        prefix = "pqcrystals_kyber1024_ref_"

    keypair = getattr(lib, prefix + "keypair")
    enc     = getattr(lib, prefix + "enc")
    dec     = getattr(lib, prefix + "dec")

    keypair.argtypes = [C.POINTER(C.c_ubyte), C.POINTER(C.c_ubyte)]
    keypair.restype  = C.c_int

    enc.argtypes = [C.POINTER(C.c_ubyte),
                    C.POINTER(C.c_ubyte),
                    C.POINTER(C.c_ubyte)]
    enc.restype  = C.c_int

    dec.argtypes = [C.POINTER(C.c_ubyte),
                    C.POINTER(C.c_ubyte),
                    C.POINTER(C.c_ubyte)]
    dec.restype  = C.c_int

    return keypair, enc, dec


def resolve_pake_api(lib):
    init_start = lib.initStart
    init_end   = lib.initEnd
    resp       = lib.resp

    U8P = C.POINTER(C.c_ubyte)

    init_start.argtypes = [U8P, U8P, U8P, U8P, U8P]
    init_start.restype  = None

    init_end.argtypes   = [U8P, U8P, U8P, U8P, U8P, U8P]
    init_end.restype    = C.c_int

    resp.argtypes       = [U8P, U8P, U8P, U8P, U8P]
    resp.restype        = None

    return init_start, init_end, resp


# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------

def samplentt_sanity(gen_matrix):
    seed = bytearray(random_seed(32))
    mat1 = ((C.c_int16 * KYBER_N) * 4 * 4)()
    mat2 = ((C.c_int16 * KYBER_N) * 4 * 4)()

    # coefficients in [0, q-1]
    gen_matrix(mat1, (C.c_uint8 * 32).from_buffer(seed), 0)
    for i in range(4):
        for j in range(4):
            for t in range(KYBER_N):
                if mat1[i][j][t] >= KYBER_Q:
                    raise SystemExit("[FAIL] SampleNTT: coefficient out of bounds")


def kem_sanity(keypair, enc, dec, k_idx: int, kem_label: str, algo_label: str):
    pk_len = PK_SIZES[k_idx]
    sk_len = SK_SIZES[k_idx]
    ct_len = CT_SIZES[k_idx]

    pk  = (C.c_ubyte * pk_len)()
    sk  = (C.c_ubyte * sk_len)()
    ct  = (C.c_ubyte * ct_len)()
    ss1 = (C.c_ubyte * SS_LEN)()
    ss2 = (C.c_ubyte * SS_LEN)()

    if keypair(pk, sk) != 0:
        raise SystemExit(f"[FAIL] {kem_label} / {algo_label}: keypair failed")
    if enc(ct, ss1, pk) != 0:
        raise SystemExit(f"[FAIL] {kem_label} / {algo_label}: enc failed")
    if dec(ss2, ct, sk) != 0:
        raise SystemExit(f"[FAIL] {kem_label} / {algo_label}: dec failed")
    if bytes(ss1) != bytes(ss2):
        raise SystemExit(f"[FAIL] {kem_label} / {algo_label}: shared secrets mismatch")


def pake_sanity(init_start, init_end, resp, k_idx: int, label: str, algo_label: str):
    pk_len = PK_SIZES[k_idx]
    sk_len = SK_SIZES[k_idx]
    ct_len = CT_SIZES[k_idx]

    msg1_len = pk_len + KYBER_SYMBYTES
    msg2_len = ct_len + KYBER_SYMBYTES
    pw_len   = KYBER_SYMBYTES

    pw  = (C.c_ubyte * pw_len).from_buffer_copy(random_seed(pw_len))
    sid = (C.c_ubyte * pw_len).from_buffer_copy(random_seed(pw_len))

    msg1 = (C.c_ubyte * msg1_len)()
    msg2 = (C.c_ubyte * msg2_len)()
    pk   = (C.c_ubyte * pk_len)()
    sk   = (C.c_ubyte * sk_len)()
    key_init = (C.c_ubyte * pw_len)()
    key_resp = (C.c_ubyte * pw_len)()

    init_start(msg1, pk, sk, pw, sid)
    resp(key_resp, msg2, msg1, pw, sid)
    rc = init_end(key_init, msg2, msg1, pk, sk, sid)

    if rc != 0:
        raise SystemExit(f"[FAIL] {label} / {algo_label}: initEnd failed")
    if bytes(key_init) != bytes(key_resp):
        raise SystemExit(f"[FAIL] {label} / {algo_label}: PAKE key mismatch")


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

def bench_gen_matrix(gen_matrix, k: int) -> float:
    seed = bytearray(random_seed(32))
    matrix = ((C.c_int16 * KYBER_N) * 4 * 4)()
    start = time.perf_counter()
    for _ in range(NUM_RUNS):
        gen_matrix(matrix, (C.c_uint8 * 32).from_buffer(seed), 0)
    end = time.perf_counter()
    return 1000.0 * (end - start) / NUM_RUNS

def bench_kem(keypair, enc, dec, k_idx: int) -> float:
    pk_len = PK_SIZES[k_idx]
    sk_len = SK_SIZES[k_idx]
    ct_len = CT_SIZES[k_idx]

    pk  = (C.c_ubyte * pk_len)()
    sk  = (C.c_ubyte * sk_len)()
    ct  = (C.c_ubyte * ct_len)()
    ss1 = (C.c_ubyte * SS_LEN)()
    ss2 = (C.c_ubyte * SS_LEN)()

    start = time.perf_counter()
    for _ in range(NUM_RUNS):
        if keypair(pk, sk) != 0:
            raise SystemExit("keypair failed in benchmark")
        if enc(ct, ss1, pk) != 0:
            raise SystemExit("enc failed in benchmark")
        if dec(ss2, ct, sk) != 0:
            raise SystemExit("dec failed in benchmark")
        if bytes(ss1) != bytes(ss2):
            raise SystemExit("shared secrets mismatch in benchmark")
    end = time.perf_counter()
    return 1000.0 * (end - start) / NUM_RUNS


def bench_pake(init_start, init_end, resp, k_idx: int):
    """Benchmark each NoIC phase separately.

    Returns a tuple of average ms per run for (initStart, resp, initEnd).
    """
    pk_len = PK_SIZES[k_idx]
    sk_len = SK_SIZES[k_idx]
    ct_len = CT_SIZES[k_idx]

    msg1_len = pk_len + KYBER_SYMBYTES
    msg2_len = ct_len + KYBER_SYMBYTES
    pw_len   = KYBER_SYMBYTES

    pw  = (C.c_ubyte * pw_len).from_buffer_copy(random_seed(pw_len))
    sid = (C.c_ubyte * pw_len).from_buffer_copy(random_seed(pw_len))

    msg1 = (C.c_ubyte * msg1_len)()
    msg2 = (C.c_ubyte * msg2_len)()
    pk   = (C.c_ubyte * pk_len)()
    sk   = (C.c_ubyte * sk_len)()
    key_init = (C.c_ubyte * pw_len)()
    key_resp = (C.c_ubyte * pw_len)()

    # Produce valid state (msg1, pk, sk, msg2) for the resp/initEnd loops,
    # and confirm the protocol succeeds before timing.
    init_start(msg1, pk, sk, pw, sid)
    resp(key_resp, msg2, msg1, pw, sid)
    rc = init_end(key_init, msg2, msg1, pk, sk, sid)
    if rc != 0 or bytes(key_init) != bytes(key_resp):
        raise SystemExit("PAKE failure during benchmark")

    # Bench initStart
    start = time.perf_counter()
    for _ in range(NUM_RUNS):
        init_start(msg1, pk, sk, pw, sid)
    end = time.perf_counter()
    t_init_start = 1000.0 * (end - start) / NUM_RUNS

    # Bench resp
    start = time.perf_counter()
    for _ in range(NUM_RUNS):
        resp(key_resp, msg2, msg1, pw, sid)
    end = time.perf_counter()
    t_resp = 1000.0 * (end - start) / NUM_RUNS

    # Bench initEnd
    start = time.perf_counter()
    for _ in range(NUM_RUNS):
        rc = init_end(key_init, msg2, msg1, pk, sk, sid)
    end = time.perf_counter()
    t_init_end = 1000.0 * (end - start) / NUM_RUNS

    if rc != 0 or bytes(key_init) != bytes(key_resp):
        raise SystemExit("PAKE failure during benchmark")

    return t_init_start, t_resp, t_init_end


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    k_values = [2, 3, 4]

    samplentt_timings = [[0.0] * NUM_ALGOS for _ in range(NUM_K)]
    kem_timings       = [[0.0] * NUM_ALGOS for _ in range(NUM_K)]
    pake_init_start_timings = [[0.0] * NUM_ALGOS for _ in range(NUM_K)]
    pake_resp_timings       = [[0.0] * NUM_ALGOS for _ in range(NUM_K)]
    pake_init_end_timings   = [[0.0] * NUM_ALGOS for _ in range(NUM_K)]

    # 1) Sanity checks: each library exactly once
    print("Running sanity checks...")
    for k_idx in range(NUM_K):
        for a in range(NUM_ALGOS):
            lib = C.CDLL(LIB_PATHS[k_idx][a])

            gen_matrix = resolve_gen_matrix(lib, k_idx)
            samplentt_sanity(gen_matrix)

            keypair, enc, dec = resolve_kyber_api(lib, k_idx)
            kem_sanity(keypair, enc, dec, k_idx, kem_labels[k_idx], algo_names[a])

            init_start, init_end, resp = resolve_pake_api(lib)
            pake_sanity(init_start, init_end, resp, k_idx, pake_labels[k_idx], algo_names[a])
    print("[OK] All sanity checks passed\n")

    # 2) Benchmarks: each library loaded once more
    print(f"Benchmarking gen_matrix ({NUM_RUNS} runs)...")
    for k_idx, k in enumerate(k_values):
        for a in range(NUM_ALGOS):
            lib = C.CDLL(LIB_PATHS[k_idx][a])
            gen_matrix = resolve_gen_matrix(lib, k_idx)
            t = bench_gen_matrix(gen_matrix, k)
            samplentt_timings[k_idx][a] = t
            print(f"... {kem_labels_gen[k_idx]} / {algo_names[a]}: {t:.4f} ms")

    print(f"\nBenchmarking KEM keygen+enc+dec ({NUM_RUNS} runs)...")
    for k_idx in range(NUM_K):
        for a in range(NUM_ALGOS):
            lib = C.CDLL(LIB_PATHS[k_idx][a])
            keypair, enc, dec = resolve_kyber_api(lib, k_idx)
            t = bench_kem(keypair, enc, dec, k_idx)
            kem_timings[k_idx][a] = t
            print(f"... {kem_labels[k_idx]} / {algo_names[a]}: {t:.4f} ms")

    print(f"\nBenchmarking NoIC PAKE ({NUM_RUNS} runs)...")
    for k_idx in range(NUM_K):
        for a in range(NUM_ALGOS):
            lib = C.CDLL(LIB_PATHS[k_idx][a])
            init_start, init_end, resp = resolve_pake_api(lib)
            t_is, t_resp, t_ie = bench_pake(init_start, init_end, resp, k_idx)
            pake_init_start_timings[k_idx][a] = t_is
            pake_resp_timings[k_idx][a]       = t_resp
            pake_init_end_timings[k_idx][a]   = t_ie
            print(f"... {pake_labels[k_idx]} / {algo_names[a]}: "
                  f"initStart {t_is:.4f} ms | resp {t_resp:.4f} ms | "
                  f"initEnd {t_ie:.4f} ms")

    # 3) Print tables
    print("\nSampleNTT results (gen_matrix; cycles per run with RSD%)\n")
    print("Algorithm A0 : FIPS 203")
    print("Algorithm A1 : Fixed Loop Sampler (FLS)")
    print("Algorithm B0 : Repeated Modular Division (RMD)")
    print("Algorithm C0 : Single Modular Division OpenSSL")
    print("Algorithm C1 : Single Modular Division (SMD)")
    print_table(kem_labels_gen, algo_names, samplentt_timings)

    print("\nKEM results (keygen+enc+dec, average ms per run)\n")
    print_table(kem_labels, algo_names, kem_timings)

    print("\nPAKE results (NoIC initStart, average ms per run)\n")
    print_table(pake_labels, algo_names, pake_init_start_timings)

    print("\nPAKE results (NoIC resp, average ms per run)\n")
    print_table(pake_labels, algo_names, pake_resp_timings)

    print("\nPAKE results (NoIC initEnd, average ms per run)\n")
    print_table(pake_labels, algo_names, pake_init_end_timings)


if __name__ == "__main__":
    main()
