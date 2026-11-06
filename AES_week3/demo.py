"""Demo AES-128 cho một khối, văn bản và tệp."""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

from aes import AES, decrypt_file, derive_key, encrypt_file

DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f"
DEFAULT_PLAINTEXT = "00112233445566778899aabbccddeeff"
EXPECTED_CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a"


def hex_block(value: str) -> bytes:
    try:
        block = bytes.fromhex(value)
    except ValueError as err:
        raise argparse.ArgumentTypeError("Cần nhập chuỗi hex hợp lệ (ví dụ: 001122...)") from err
    if len(block) != 16:
        raise argparse.ArgumentTypeError(
            f"Yêu cầu chính xác 16 byte (32 ký tự hex), nhận được {len(block)} byte"
        )
    return block


def print_matrix_state(round_no: int, step: str, value: bytes) -> None:
    """In từng hàng của state được lưu theo thứ tự cột."""
    print(f"Round {round_no:02d} | {step:<14} | {value.hex()}")
    for row in range(4):
        print("    " + " ".join(f"{value[4 * col + row]:02x}" for col in range(4)))


def run_single_block_demo(plaintext: bytes, key: bytes, trace: bool) -> None:
    print("AES-128 · Một khối 16 byte")
    print(f"Bản rõ: {plaintext.hex()}")
    print(f"Khóa: {key.hex()}")

    aes = AES(key)
    callback = print_matrix_state if trace else None
    if trace:
        print("\nMã hóa")
    ciphertext = aes.encrypt_block(plaintext, trace=callback)
    if trace:
        print("\nGiải mã")
    recovered = aes.decrypt_block(ciphertext, trace=callback)

    print(f"\nBản mã: {ciphertext.hex()}")
    print(f"Bản rõ khôi phục: {recovered.hex()}")
    if plaintext.hex() == DEFAULT_PLAINTEXT and key.hex() == DEFAULT_KEY:
        fips_pass = ciphertext.hex() == EXPECTED_CIPHERTEXT
        print(f"Đối chiếu NIST C.1: {'PASS' if fips_pass else 'FAIL'}")
    print(f"Kiểm tra hai chiều: {'PASS' if recovered == plaintext else 'FAIL'}")


def run_text_cbc_demo(text: str, key: bytes) -> None:
    data = text.encode("utf-8")
    aes = AES(key)
    iv, ciphertext = aes.encrypt_cbc(data)
    recovered = aes.decrypt_cbc(ciphertext, iv).decode("utf-8")

    print("AES-128-CBC · Văn bản UTF-8")
    print(f'Văn bản gốc: "{text}" ({len(data)} byte)')
    print(f"Khóa: {key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Bản mã: {ciphertext.hex()} ({len(ciphertext)} byte)")
    print(f'Văn bản khôi phục: "{recovered}"')
    print(f"Kiểm tra hai chiều: {'PASS' if recovered == text else 'FAIL'}")


def run_zip_file_demo(key: bytes) -> None:
    work_dir = Path(__file__).resolve().parent
    sample_zip = work_dir / "sample_archive.zip"
    encrypted_file = work_dir / "sample_archive.zip.enc"
    recovered_zip = work_dir / "sample_archive_recovered.zip"

    with zipfile.ZipFile(sample_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("baocao_pbl3.txt", "Báo cáo tiến độ - Học phần Mạng thông tin máy tính PBL3.")
        archive.writestr(
            "data/students.csv",
            "id,name,role\n1,Nguyen Thai Hoang,Student\n2,Le Truong Uyen Nhi,Student\n",
        )

    iv, sha256_orig = encrypt_file(sample_zip, encrypted_file, key=key)
    sha256_rec = decrypt_file(encrypted_file, recovered_zip, key=key)

    print("AES-128-CBC · Tệp ZIP")
    print(f"Tệp gốc: {sample_zip.name}")
    print(f"Tệp mã hóa: {encrypted_file.name}")
    print(f"Tệp khôi phục: {recovered_zip.name}")
    print(f"IV: {iv.hex()}")
    print(f"SHA-256 gốc: {sha256_orig}")
    print(f"SHA-256 khôi phục: {sha256_rec}")
    print(f"Đối chiếu SHA-256: {'PASS' if sha256_orig == sha256_rec else 'FAIL'}")

    with zipfile.ZipFile(recovered_zip) as archive:
        print("Tệp trong ZIP: " + ", ".join(archive.namelist()))
        content = archive.read("baocao_pbl3.txt").decode("utf-8")
        print(f"baocao_pbl3.txt: {content}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key", type=hex_block, default=DEFAULT_KEY,
        help="Khóa 16 byte dạng hex (mặc định: FIPS C.1)"
    )
    parser.add_argument("--password", help="Mật khẩu để dẫn xuất khóa qua PBKDF2")
    parser.add_argument(
        "--plaintext", type=hex_block, default=DEFAULT_PLAINTEXT,
        help="Bản rõ 16 byte dạng hex (mặc định: FIPS C.1)"
    )
    parser.add_argument("--text", help="Văn bản cần mã hóa CBC")
    parser.add_argument("--trace", action="store_true", help="In ma trận ở từng bước")
    parser.add_argument("--demo-zip", action="store_true", help="Chạy demo với tệp ZIP")
    parser.add_argument("--encrypt-file", help="Tệp cần mã hóa")
    parser.add_argument("--decrypt-file", help="Tệp cần giải mã")
    parser.add_argument("--out", help="Tệp đầu ra")

    args = parser.parse_args()
    password = args.password or None
    file_key = args.key if password is None else None

    try:
        if args.encrypt_file:
            out_path = args.out or args.encrypt_file + ".enc"
            iv, sha = encrypt_file(args.encrypt_file, out_path, key=file_key, password=password)
            print(f"Đã mã hóa: {args.encrypt_file} -> {out_path}")
            print(f"IV: {iv.hex()}")
            print(f"SHA-256 gốc: {sha}")
            return

        if args.decrypt_file:
            if not args.out:
                parser.error("Giải mã tệp cần --out <đường_dẫn>")
            sha = decrypt_file(args.decrypt_file, args.out, key=file_key, password=password)
            print(f"Đã giải mã: {args.decrypt_file} -> {args.out}")
            print(f"SHA-256 khôi phục: {sha}")
            return

        key = args.key
        if password is not None:
            key, salt = derive_key(password)
            print(f"Salt PBKDF2: {salt.hex()}")

        if args.demo_zip:
            run_zip_file_demo(key)
        elif args.text is not None:
            run_text_cbc_demo(args.text, key)
        else:
            run_single_block_demo(args.plaintext, key, args.trace)

    except ValueError as err:
        print(f"Lỗi: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (OSError, ValueError):
                pass
    main()
