"""Mã hóa và giải mã một khối AES-128, sau đó xác minh bản rõ được khôi phục."""

import argparse
import sys

# Đảm bảo mã hóa UTF-8 cho stdout/stderr khi chạy trên Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from aes import ROUNDS, decrypt_block, encrypt_block

# Các hằng số kiểm thử mặc định từ tiêu chuẩn FIPS 197 (Phụ lục C.1)
DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f"
DEFAULT_PLAINTEXT = "00112233445566778899aabbccddeeff"
EXPECTED_CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a"


def hex_block(value: str) -> bytes:
    """Chuyển đổi chuỗi hex thành khối 16 byte."""
    try:
        block = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Sử dụng các byte thập lục phân (hex), ví dụ: 001122...") from error
    if len(block) != 16:
        raise argparse.ArgumentTypeError("Cần chính xác 16 byte (32 chữ số thập lục phân)")
    return block


def print_step(round_number: int, step: str, value: bytes) -> None:
    """In trạng thái trung gian của một bước theo từng vòng dưới dạng hex và ma trận 4x4."""
    print(f"Round {round_number:02d} | {step:<14} | {value.hex()}")
    for row in range(4):
        print("    " + " ".join(f"{value[4 * column + row]:02x}" for column in range(4)))


def print_decrypt_step(round_number: int, step: str, value: bytes) -> None:
    """In trạng thái của bước giải mã, hiển thị rõ thứ tự khóa vòng tương ứng."""
    if step == "RoundKey":
        step = f"RoundKey K{ROUNDS - round_number}"
    print_step(round_number, step, value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key",
        type=hex_block,
        default=DEFAULT_KEY,
        help="Khóa 128-bit dạng chuỗi hex (mặc định: vector kiểm thử FIPS 197)",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--plaintext",
        type=hex_block,
        help="Bản rõ 16-byte dạng chuỗi hex (mặc định: vector kiểm thử FIPS 197)",
    )
    source.add_argument(
        "--text",
        help="Văn bản UTF-8 có độ dài mã hóa chính xác 16 byte",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Hiển thị từng trạng thái dưới dạng hex và ma trận 4x4",
    )
    args = parser.parse_args()

    if args.text is not None:
        plaintext = args.text.encode("utf-8")
        if len(plaintext) != 16:
            parser.error(f"Văn bản UTF-8 phải có độ dài đúng 16 byte; nhận được {len(plaintext)}")
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
