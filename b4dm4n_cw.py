#!/usr/bin/env python3
"""
b4dm4n-cw — Cryptographic Weapon
=================================

CLI wrapper for 1nf1D3L's Kyber — Non-FIPS Post-Quantum KEM
"Compliance is for auditors. Security is for survivors."

Usage: b4dm4n-cw <command> [options]

Commands:
  keygen       Generate 1nf1D3L Kyber keypair
  encaps       Encapsulate to a public key
  decaps       Decapsulate with a private key
  hybrid-keygen  Generate hybrid ECDH+Kyber keypair
  hybrid-encaps  Hybrid encapsulation (ECDH + Kyber)
  hybrid-decaps  Hybrid decapsulation (ECDH + Kyber)
  bench        Run performance benchmarks
  info         Show cryptographic parameters
  art          Display the Coffee Protocol ASCII art

Examples:
  b4dm4n-cw keygen -o mykeys
  b4dm4n-cw encaps -k mykeys.pk -o ct.bin
  b4dm4n-cw decaps -k mykeys.sk -c ct.bin
  b4dm4n-cw bench -n 100
  b4dm4n-cw art
"""

import argparse
import sys
import os
import time
import secrets
import base64

sys.path.insert(0, os.path.dirname(__file__))
from inf1del_kyber import Inf1delKyber


B4DM4N_LOGO = r"""
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║  ██████╗ ██████╗  █████╗ ██████╗ ███████╗███████╗███████╗███╗  ██║  ║
    ║  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██════╝████╗ ██║  ║
    ║  ██████╔╝██████╔╝███████║██████╔╝█████╗  ███████╗█████╗  ██╔██╗██║  ║
    ║  ██╔═══╝ ██╔══██╗██══██║██══██╗██══╝  ╚════██║██════╝██║╚████║  ║
    ║  ██║     ██║  ██║██║  ██║██║  ██║███████╗███████║███████╗██║ ╚███║  ║
    ║  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚══╝  ║
    ║                                                                      ║
    ║     ─  c w  ─    C R Y P T O G R A P H I C   W E A P O N           ║
    ║                                                                      ║
    ║    "brew crypto. stay paranoid. survive."                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
"""

COFFEE_SNAKE = r"""
     ╔════════════════════════════════════════════════════════════════════════════════╗
     ║                        ☕  THE COFFEE PROTOCOL  ☕                           ║
     ║                 "Compliance is for auditors. Security is for survivors."   ║
     ╚════════════════════════════════════════════════════════════════════════════════╝
                                                                                   
                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                         ▄████████████████████████████████████████▄
                        █████████████████████████████████████████████
                       ███████████████████████████████████████████████
                      █████████████████████████████████████████████████
                     ███████████████████████████████████████████████████
                    █████████████████████████████████████████████████████
                   ███████████████████████████████████████████████████████
                  █████████████████████████████████████████████████████████
                  ██████████████████████████████████████████████████████████
                   █████████████████████████████████████████████████████████
                    ████████████████████████████████████████████████████████
                     ███████████████████████████████████████████████████████
                      ██████████████████████████████████████████████████████
                       █████████████████████████████████████████████████████
                        ████████████████████████████████████████████████████
                         ███████████████████████████████████████████████████
                          ██████████████████████████████████████████████████
                           █████████████████████████████████████████████████
                            ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                                 │
                                 │              ☕
                                 │             ╱╲
                                 │            ╱██╲
                                 │           ╱████╲
                                 │          ╱██████╲
                                 │         ╱████████╲
                                 │        ╱██████████╲
                                 ▼       ╱████████████╲
                                ▄█████████████████████▄
                               ████████████████████████
                              ██████████████████████████
                             ████████████████████████████
                            ██████████████████████████████
                           ████████████████████████████████
                          ██████████████████████████████████
                         ████████████████████████████████████
                        ██████████████████████████████████████
                        ██████████████████████████████████████
                         █████████████████████████████████████
                          ████████████████████████████████████
                           ███████████████████████████████████
                            █████████████████████████████████
                             ███████████████████████████████
                              █████████████████████████████
                               ███████████████████████████
                                █████████████████████████
                                 ██████████████████████
                                  ████████████████████
                                   ██████████████████
                                    ████████████████
                                     █████████████
                                      ███████████
                                       █████████
                                        ███████
                                         █████
                                          ███
                                           ▀
                                          ▄▄▄
                                         █████
                                        ███████
                                       █████████
                                      ███████████
                                     █████████████
                                    ███████████████
                                   █████████████████
                                  ███████████████████
                                  ███████████████████
                                   ██████████████████
                                    ████████████████
                                     █████████████
                                      ███████████
                                       █████████
                                        ███████
                                         █████
                                          ███
                                           ▀
     ☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕☕
"""

TEAPOT_SNAKE_ART = COFFEE_SNAKE


INFO_ART = r"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    1nf1D3L's Kyber — Cryptographic Parameters               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Variant:           ML-KEM-768 (Non-FIPS, 1nf1D3L modifications)            ║
║  Security Level:    NIST Level 3 (equivalent) — ~192-bit classical          ║
║  Lattice:           Module-LWE over R_q = Z_q[X]/(X^256 + 1)                ║
║  Modulus q:         3329 (NTT-friendly prime)                               ║
║  Dimension n:       256                                                     ║
║  Module rank k:     3                                                       ║
║                                                                             ║
║  1nf1D3L Modifications (Non-FIPS):                                          ║
║  ─────────────────────────────────────────                                  ║
║  • Noise distribution: η₁ = 3, η₂ = 3 (wider than FIPS η=2)                ║
║    → Wider centered binomial distribution → more entropy                   ║
║    → Slightly larger ciphertext, stronger concrete security                ║
║  • Domain separation tag: "1NF1D3L-KYBER-V1" on all hash/KDF inputs        ║
║    → Domain separation from FIPS ML-KEM                                     ║
║    → Prevents cross-protocol attacks                                        ║
║  • NTT twiddle factor perturbation: per-session random twiddles            ║
║    → Side-channel resistance through domain randomization                  ║
║    → Each session uses unique NTT roots                                     ║
║  • Coffee-protocol binding: recipe string mixed into KDF                   ║
║    → Domain separation per coffee recipe (espresso, latte, etc.)           ║
║  • Extra key confirmation round (re-encapsulation check)                   ║
║    → Stronger CCA2 security in practice                                     ║
║                                                                             ║
║  Parameter Sizes (1nf1D3L-KYBER-768):                                       ║
║  ──────────────────────────────────                                         ║
║  • Public key:       1184 bytes  (ρ:32 + t:384×3)                          ║
║  • Private key:      2400 bytes  (s_ntt:384×3 + pk:11 + h(pk):32 + z:32)        ║
║  • Ciphertext:       1120 bytes  (u:320×3 + v:128 + session_seed:32)       ║
║  • Shared secret:    32 bytes                                              ║
║                                                                             ║
║  Hybrid Variant (ECDH P-256 + 1nf1D3L Kyber):                              ║
║  ────────────────────────────────────────────                              ║
║  • Hybrid PK:       ~1251 bytes  (ECC_len:2 + ECC_pk:65 + Kyber_pk:1184)   ║
║  • Hybrid SK:       ~2432 bytes  (ECC_seed:32 + Kyber_sk:2400)             ║
║  • Hybrid CT:       ~1155 bytes  (ECC_ephem_len:2 + ECC_ephem:65 + Kyber_ct)║
║  • Hybrid SS:       32 bytes   (HKDF-SHA3-256(ECDH_SS || Kyber_SS))        ║
║                                                                             ║
║  Security Properties:                                                       ║
║  ──────────────────                                                         ║
║  ✓ IND-CCA2 secure (via re-encapsulation check)                            ║
║  ✓ Post-quantum: secure against CRQC (CRQC-resistant)                      ║
║  ✓ Side-channel resistant: NTT twiddle perturbation + constant-time ops   ║
║  ✓ Domain separated: unique tags prevent cross-protocol attacks            ║
║  ✓ Recipe-bound: coffee recipe domain separation                           ║
║  ✗ NOT FIPS 203 compliant (by design — η=3, custom domain tags)           ║
║  ✓ Suitable for: coffee protocols, red teaming, research, survival        ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""


def print_banner(show_snake=True):
    print(B4DM4N_LOGO)
    if show_snake:
        print(COFFEE_SNAKE)


def print_art():
    print(B4DM4N_LOGO)
    print(COFFEE_SNAKE)


def print_info():
    print(INFO_ART)


def cmd_keygen(args):
    recipe = args.recipe or "espresso"
    print_banner()
    print(f"\n[+] Generating 1nf1D3L Kyber keypair (recipe: {recipe})...\n")
    
    pk, sk = Inf1delKyber.keygen(recipe)
    
    if args.output:
        with open(args.output + ".pk", "wb") as f:
            f.write(pk)
        with open(args.output + ".sk", "wb") as f:
            f.write(sk)
        print(f"[+] Public key saved to:  {args.output}.pk ({len(pk)} bytes)")
        print(f"[+] Private key saved to: {args.output}.sk ({len(sk)} bytes)")
    else:
        print(f"Public Key  ({len(pk)} bytes):")
        print(pk.hex())
        print()
        print(f"Private Key ({len(sk)} bytes):")
        print(sk.hex())
    
    if args.b64:
        print(f"\nPublic Key (base64):  {base64.b64encode(pk).decode()}")
        print(f"Private Key (base64): {base64.b64encode(sk).decode()}")


def cmd_encaps(args):
    recipe = args.recipe or "espresso"
    print_banner()
    
    with open(args.pubkey, "rb") as f:
        pk = f.read()
    
    print(f"\n[+] Encapsulating to public key ({len(pk)} bytes, recipe: {recipe})...\n")
    
    ct, ss = Inf1delKyber.encaps(pk, recipe)
    
    if args.output:
        with open(args.output, "wb") as f:
            f.write(ct)
        print(f"[+] Ciphertext saved to: {args.output} ({len(ct)} bytes)")
    else:
        print(f"Ciphertext ({len(ct)} bytes):")
        print(ct.hex())
    
    print(f"\nShared Secret (32 bytes):")
    print(ss.hex())
    
    if args.b64:
        print(f"\nCiphertext (base64):  {base64.b64encode(ct).decode()}")
        print(f"Shared Secret (base64): {base64.b64encode(ss).decode()}")


def cmd_decaps(args):
    recipe = args.recipe or "espresso"
    print_banner()
    
    with open(args.privkey, "rb") as f:
        sk = f.read()
    with open(args.ciphertext, "rb") as f:
        ct = f.read()
    
    print(f"\n[+] Decapsulating ciphertext ({len(ct)} bytes, recipe: {recipe})...\n")
    
    ss = Inf1delKyber.decaps(sk, ct, recipe)
    
    print(f"Shared Secret (32 bytes):")
    print(ss.hex())
    
    if args.b64:
        print(f"\nShared Secret (base64): {base64.b64encode(ss).decode()}")


def cmd_hybrid_keygen(args):
    recipe = args.recipe or "espresso"
    print_banner()
    print(f"\n[+] Generating Hybrid ECDH+1nf1D3L Kyber keypair (recipe: {recipe})...\n")
    
    pk, sk = Inf1delKyber.hybrid_keygen(recipe=recipe)
    
    if args.output:
        with open(args.output + ".hp", "wb") as f:
            f.write(pk)
        with open(args.output + ".hs", "wb") as f:
            f.write(sk)
        print(f"[+] Hybrid public key saved to:  {args.output}.hp ({len(pk)} bytes)")
        print(f"[+] Hybrid private key saved to: {args.output}.hs ({len(sk)} bytes)")
    else:
        print(f"Hybrid Public Key  ({len(pk)} bytes):")
        print(pk.hex())
        print()
        print(f"Hybrid Private Key ({len(sk)} bytes):")
        print(sk.hex())


def cmd_hybrid_encaps(args):
    recipe = args.recipe or "espresso"
    print_banner()
    
    with open(args.pubkey, "rb") as f:
        pk = f.read()
    
    print(f"\n[+] Hybrid encapsulating to public key ({len(pk)} bytes, recipe: {recipe})...\n")
    
    ct, ss = Inf1delKyber.hybrid_encapsulate(pk, recipe)
    
    if args.output:
        with open(args.output, "wb") as f:
            f.write(ct)
        print(f"[+] Ciphertext saved to: {args.output} ({len(ct)} bytes)")
    else:
        print(f"Ciphertext ({len(ct)} bytes):")
        print(ct.hex())
    
    print(f"\nShared Secret (32 bytes):")
    print(ss.hex())


def cmd_hybrid_decaps(args):
    recipe = args.recipe or "espresso"
    print_banner()
    
    with open(args.privkey, "rb") as f:
        sk = f.read()
    with open(args.ciphertext, "rb") as f:
        ct = f.read()
    
    print(f"\n[+] Hybrid decapsulating ciphertext ({len(ct)} bytes, recipe: {recipe})...\n")
    
    ss = Inf1delKyber.hybrid_decapsulate(sk, ct, recipe)
    
    print(f"Shared Secret (32 bytes):")
    print(ss.hex())


def cmd_benchmark(args):
    recipe = args.recipe or "espresso"
    iterations = args.iterations
    
    print_banner()
    print(f"\n[+] Benchmarking 1nf1D3L Kyber (recipe: {recipe}) — {iterations} iterations...\n")
    
    # KeyGen
    start = time.perf_counter()
    for _ in range(iterations):
        pk, sk = Inf1delKyber.keygen(recipe)
    kg_time = (time.perf_counter() - start) / iterations * 1000
    
    # Encaps
    pk, sk = Inf1delKyber.keygen(recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        ct, ss = Inf1delKyber.encaps(pk, recipe)
    enc_time = (time.perf_counter() - start) / iterations * 1000
    
    # Decaps
    ct, ss = Inf1delKyber.encaps(pk, recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        ss2 = Inf1delKyber.decaps(sk, ct, recipe)
    dec_time = (time.perf_counter() - start) / iterations * 1000
    
    assert ss == ss2, "Benchmark verification failed!"
    
    print(f"  KeyGen:   {kg_time:.2f} ms/op")
    print(f"  Encaps:   {enc_time:.2f} ms/op")
    print(f"  Decaps:   {dec_time:.2f} ms/op")
    print(f"  PK size:  {len(pk)} bytes")
    print(f"  SK size:  {len(sk)} bytes")
    print(f"  CT size:  {len(ct)} bytes")
    print(f"  SS size:  {len(ss)} bytes")
    
    # Hybrid benchmark
    print(f"\n[+] Benchmarking Hybrid ECDH+Kyber (recipe: {recipe})...\n")
    
    start = time.perf_counter()
    for _ in range(iterations):
        hpk, hsk = Inf1delKyber.hybrid_keygen(recipe=recipe)
    hkg_time = (time.perf_counter() - start) / iterations * 1000
    
    hpk, hsk = Inf1delKyber.hybrid_keygen(recipe=recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        hct, hss = Inf1delKyber.hybrid_encapsulate(hpk, recipe)
    henc_time = (time.perf_counter() - start) / iterations * 1000
    
    hct, hss = Inf1delKyber.hybrid_encapsulate(hpk, recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        hss2 = Inf1delKyber.hybrid_decapsulate(hsk, hct, recipe)
    hdec_time = (time.perf_counter() - start) / iterations * 1000
    
    assert hss == hss2, "Hybrid benchmark verification failed!"
    
    print(f"  Hybrid KeyGen:   {hkg_time:.2f} ms/op")
    print(f"  Hybrid Encaps:   {henc_time:.2f} ms/op")
    print(f"  Hybrid Decaps:   {hdec_time:.2f} ms/op")
    print(f"  Hybrid PK size:  {len(hpk)} bytes")
    print(f"  Hybrid SK size:  {len(hsk)} bytes")
    print(f"  Hybrid CT size:  {len(hct)} bytes")
    print(f"  Hybrid SS size:  {len(hss)} bytes")


def main():
    parser = argparse.ArgumentParser(
        prog="b4dm4n-cw",
        description="b4dm4n-cw — Cryptographic Weapon for 1nf1D3L's Kyber",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  b4dm4n-cw keygen -o mykeys
  b4dm4n-cw encaps -k mykeys.pk -o ct.bin
  b4dm4n-cw decaps -k mykeys.sk -c ct.bin
  b4dm4n-cw hybrid-keygen -o hybrid
  b4dm4n-cw bench -n 50
  b4dm4n-cw art
  b4dm4n-cw info
        """
    )
    parser.add_argument("--recipe", default="espresso", help="Coffee recipe for domain separation (default: espresso)")
    parser.add_argument("--b64", action="store_true", help="Also output base64 encoding")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # keygen
    p = subparsers.add_parser("keygen", help="Generate 1nf1D3L Kyber keypair")
    p.add_argument("-o", "--output", help="Output file prefix (creates .pk and .sk)")
    p.set_defaults(func=cmd_keygen)
    
    # encaps
    p = subparsers.add_parser("encaps", help="Encapsulate to a public key")
    p.add_argument("pubkey", help="Public key file")
    p.add_argument("-o", "--output", help="Output ciphertext file")
    p.set_defaults(func=cmd_encaps)
    
    # decaps
    p = subparsers.add_parser("decaps", help="Decapsulate with a private key")
    p.add_argument("privkey", help="Private key file")
    p.add_argument("ciphertext", help="Ciphertext file")
    p.set_defaults(func=cmd_decaps)
    
    # hybrid-keygen
    p = subparsers.add_parser("hybrid-keygen", help="Generate hybrid ECDH+Kyber keypair")
    p.add_argument("-o", "--output", help="Output file prefix (creates .hp and .hs)")
    p.set_defaults(func=cmd_hybrid_keygen)
    
    # hybrid-encaps
    p = subparsers.add_parser("hybrid-encaps", help="Hybrid encapsulate (ECDH + Kyber)")
    p.add_argument("pubkey", help="Hybrid public key file")
    p.add_argument("-o", "--output", help="Output ciphertext file")
    p.set_defaults(func=cmd_hybrid_encaps)
    
    # hybrid-decaps
    p = subparsers.add_parser("hybrid-decaps", help="Hybrid decapsulate (ECDH + Kyber)")
    p.add_argument("privkey", help="Hybrid private key file")
    p.add_argument("ciphertext", help="Ciphertext file")
    p.set_defaults(func=cmd_hybrid_decaps)
    
    # bench
    p = subparsers.add_parser("bench", help="Run performance benchmarks")
    p.add_argument("-n", "--iterations", type=int, default=10, help="Iterations (default: 10)")
    p.set_defaults(func=cmd_benchmark)
    
    # art
    p = subparsers.add_parser("art", help="Display Coffee Protocol ASCII art")
    p.set_defaults(func=lambda args: print_art())
    
    # info
    p = subparsers.add_parser("info", help="Show cryptographic parameters")
    p.set_defaults(func=lambda args: print_info())
    
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()