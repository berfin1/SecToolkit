#!/usr/bin/env python3
"""
SecToolkit - Hash Cracker
Identifies and cracks MD5, SHA1, SHA256 hashes using a wordlist.
WARNING: Use only on hashes you are authorized to crack.
"""

import hashlib
import argparse
import sys
import os
from datetime import datetime


HASH_LENGTHS = {
    32: "MD5",
    40: "SHA1",
    56: "SHA224",
    64: "SHA256",
    96: "SHA384",
    128: "SHA512",
}


def banner():
    print("""
╔═══════════════════════════════════════╗
║       SecToolkit - Hash Cracker       ║
║   Use only on authorized hashes       ║
╚═══════════════════════════════════════╝
    """)


def identify_hash(hash_str):
    """Identifies the hash type based on length."""
    hash_str = hash_str.strip().lower()
    length = len(hash_str)
    hash_type = HASH_LENGTHS.get(length, "Unknown")
    print(f"[*] Hash     : {hash_str}")
    print(f"[*] Length   : {length} chars")
    print(f"[*] Type     : {hash_type}")
    return hash_type, hash_str


def hash_word(word, hash_type):
    """Hashes a word with the given algorithm."""
    word_bytes = word.encode('utf-8')
    if hash_type == "MD5":
        return hashlib.md5(word_bytes).hexdigest()
    elif hash_type == "SHA1":
        return hashlib.sha1(word_bytes).hexdigest()
    elif hash_type == "SHA224":
        return hashlib.sha224(word_bytes).hexdigest()
    elif hash_type == "SHA256":
        return hashlib.sha256(word_bytes).hexdigest()
    elif hash_type == "SHA384":
        return hashlib.sha384(word_bytes).hexdigest()
    elif hash_type == "SHA512":
        return hashlib.sha512(word_bytes).hexdigest()
    return None


def crack_hash(target_hash, hash_type, wordlist_path):
    """Attempts to crack a hash using a wordlist."""
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: {wordlist_path}")
        sys.exit(1)

    print(f"[*] Wordlist : {wordlist_path}")
    print(f"[*] Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Cracking...\n")

    tried = 0
    start_time = datetime.now()

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue

                tried += 1
                hashed = hash_word(word, hash_type)

                if tried % 100000 == 0:
                    print(f"[*] Tried {tried:,} words...")

                if hashed == target_hash:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    print(f"\n[!!!] HASH CRACKED!")
                    print(f"  Hash     : {target_hash}")
                    print(f"  Password : {word}")
                    print(f"  Tried    : {tried:,} words")
                    print(f"  Time     : {elapsed:.2f} seconds")
                    return word

    except KeyboardInterrupt:
        print(f"\n[!] Interrupted after {tried:,} attempts.")
        return None

    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n[--] Hash could not be cracked.")
    print(f"  Tried : {tried:,} words")
    print(f"  Time  : {elapsed:.2f} seconds")
    return None


def crack_file(hash_file, hash_type, wordlist_path):
    """Cracks multiple hashes from a file."""
    if not os.path.exists(hash_file):
        print(f"[!] Hash file not found: {hash_file}")
        sys.exit(1)

    with open(hash_file, 'r') as f:
        hashes = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(hashes)} hashes from {hash_file}\n")
    results = {}

    for h in hashes:
        print(f"\n[*] Cracking: {h}")
        _, clean_hash = identify_hash(h)
        detected_type = HASH_LENGTHS.get(len(clean_hash), hash_type)
        result = crack_hash(clean_hash, detected_type, wordlist_path)
        results[h] = result if result else "Not found"

    print(f"\n{'='*45}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*45}")
    for h, result in results.items():
        status = "[OK]" if result != "Not found" else "[--]"
        print(f"  {status} {h[:20]}... -> {result}")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit Hash Cracker",
        epilog=(
            "Examples:\n"
            "  python hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt\n"
            "  python hash_cracker.py -f hashes.txt -w wordlist.txt\n"
            "  python hash_cracker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99"
        )
    )
    parser.add_argument("-H", "--hash", help="Single hash to crack")
    parser.add_argument("-f", "--file", help="File containing multiple hashes")
    parser.add_argument("-w", "--wordlist", help="Wordlist file path")
    parser.add_argument("--identify", help="Only identify hash type, do not crack")

    args = parser.parse_args()

    banner()

    # Only identify
    if args.identify:
        identify_hash(args.identify)
        return

    # Crack single hash
    if args.hash:
        if not args.wordlist:
            print("[!] Please provide a wordlist with -w")
            sys.exit(1)
        hash_type, clean_hash = identify_hash(args.hash)
        if hash_type == "Unknown":
            print("[!] Unknown hash type.")
            sys.exit(1)
        print("-" * 45)
        crack_hash(clean_hash, hash_type, args.wordlist)
        return

    # Crack multiple hashes from file
    if args.file:
        if not args.wordlist:
            print("[!] Please provide a wordlist with -w")
            sys.exit(1)
        crack_file(args.file, None, args.wordlist)
        return

    parser.print_help()


if __name__ == "__main__":
    main()