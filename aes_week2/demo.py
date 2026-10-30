"""Encrypt and decrypt one AES-128 block, then verify the recovered plaintext."""

import argparse

from aes import ROUNDS, decrypt_block, encrypt_block

DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f"
DEFAULT_PLAINTEXT = "00112233445566778899aabbccddeeff"
EXPECTED_CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a"


def hex_block(value: str) -> bytes:
    try:
        block = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use hexadecimal bytes, for example 001122...") from error
    if len(block) != 16:
        raise argparse.ArgumentTypeError("Expected 16 bytes (32 hexadecimal digits)")
    return block


def print_step(round_number: int, step: str, value: bytes) -> None:
    print(f"Round {round_number:02d} | {step:<14} | {value.hex()}")
    for row in range(4):
        print("    " + " ".join(f"{value[4 * column + row]:02x}" for column in range(4)))


def print_decrypt_step(round_number: int, step: str, value: bytes) -> None:
    if step == "RoundKey":
        step = f"RoundKey K{ROUNDS - round_number}"
    print_step(round_number, step, value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", type=hex_block, default=DEFAULT_KEY)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--plaintext", type=hex_block)
    source.add_argument("--text", help="UTF-8 text that encodes to exactly 16 bytes")
    parser.add_argument("--trace", action="store_true", help="Show each state as hex and a 4x4 matrix")
    args = parser.parse_args()

    if args.text is not None:
        plaintext = args.text.encode("utf-8")
        if len(plaintext) != 16:
            parser.error(f"UTF-8 text must encode to 16 bytes; received {len(plaintext)}")
    else:
        plaintext = args.plaintext if args.plaintext is not None else bytes.fromhex(DEFAULT_PLAINTEXT)

    print(f"Plaintext : {plaintext.hex()}")
    print(f"Key       : {args.key.hex()}")
    if args.trace:
        print("\nENCRYPT")
    ciphertext = encrypt_block(plaintext, args.key, trace=print_step if args.trace else None)
    print(f"Ciphertext: {ciphertext.hex()}")
    if args.trace:
        print("\nDECRYPT")
    recovered = decrypt_block(ciphertext, args.key, trace=print_decrypt_step if args.trace else None)
    print(f"Recovered : {recovered.hex()}")
    round_trip_matches = recovered == plaintext
    if args.text is not None and round_trip_matches:
        print(f"Text      : {recovered.decode('utf-8')}")
    fips_matches = True
    if plaintext.hex() == DEFAULT_PLAINTEXT and args.key.hex() == DEFAULT_KEY:
        fips_matches = ciphertext.hex() == EXPECTED_CIPHERTEXT
        print(f"FIPS C.1  : {'PASS' if fips_matches else 'FAIL'}")
    print(f"Round-trip: {'PASS' if round_trip_matches else 'FAIL'}")
    if not fips_matches or not round_trip_matches:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
