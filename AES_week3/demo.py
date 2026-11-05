"""Chương trình tương tác Demo AES-128 (Tuần 3):
- Chế độ 1: Mã hóa/giải mã một khối 16 byte chuẩn FIPS 197 C.1 (hỗ trợ cờ --trace hiển thị ma trận 4x4).
- Chế độ 2: Mã hóa/giải mã chuỗi văn bản UTF-8 bất kỳ với PKCS#7 Padding và Chế độ CBC.
- Chế độ 3: Mã hóa và giải mã File / File ZIP đa năng với Vector khởi tạo (IV) và kiểm tra toàn vẹn SHA-256.
- Chế độ 4: Tự động chạy kịch bản demo tạo & mã hóa file ZIP thực tế (--demo-zip).
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import zipfile
from pathlib import Path

# Cấu hình UTF-8 cho Windows Console
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

from aes import (
    AES,
    decrypt_file,
    derive_key,
    encrypt_file,
    generate_key,
    matrix2bytes,
)

DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f"
DEFAULT_PLAINTEXT = "00112233445566778899aabbccddeeff"
EXPECTED_CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a"


def hex_block(value: str) -> bytes:
    """Chuyển đổi chuỗi hex thành khối 16 byte."""
    try:
        block = bytes.fromhex(value)
    except ValueError as err:
        raise argparse.ArgumentTypeError("Cần nhập chuỗi hex hợp lệ (ví dụ: 001122...)") from err
    if len(block) != 16:
        raise argparse.ArgumentTypeError(f"Yêu cầu chính xác 16 byte (32 ký tự hex), nhận được {len(block)} byte")
    return block


def print_matrix_state(round_no: int, step: str, value: bytes) -> None:
    """In trạng thái State dạng hex tuyến tính và ma trận 4x4 theo thứ tự cột."""
    print(f"Round {round_no:02d} | {step:<14} | {value.hex()}")
    for row in range(4):
        print("    " + " ".join(f"{value[4 * col + row]:02x}" for col in range(4)))


def run_single_block_demo(plaintext: bytes, key: bytes, trace: bool) -> None:
    """Chạy demo mã hóa và giải mã 1 block chuẩn."""
    print("=" * 70)
    print("DEMO 1: MÃ HÓA VÀ GIẢI MÃ MỘT KHỐI 16 BYTE (FIPS 197 C.1)")
    print("=" * 70)
    print(f"Bản rõ (Plaintext) : {plaintext.hex()}")
    print(f"Khóa (Key 128-bit) : {key.hex()}")

    aes = AES(key)

    if trace:
        print("\n--- QUÁ TRÌNH MÃ HÓA (ENCRYPT TRACE) ---")
        ciphertext = aes.encrypt_block(plaintext, trace=print_matrix_state)
        print("\n--- QUÁ TRÌNH GIẢI MÃ (DECRYPT TRACE) ---")
        recovered = aes.decrypt_block(ciphertext, trace=print_matrix_state)
    else:
        ciphertext = aes.encrypt_block(plaintext)
        recovered = aes.decrypt_block(ciphertext)

    print("\n" + "-" * 70)
    print(f"Bản mã (Ciphertext): {ciphertext.hex()}")
    print(f"Bản rõ khôi phục   : {recovered.hex()}")

    fips_match = (plaintext.hex() == DEFAULT_PLAINTEXT and key.hex() == DEFAULT_KEY)
    if fips_match:
        fips_pass = ciphertext.hex() == EXPECTED_CIPHERTEXT
        print(f"Đối chiếu NIST C.1 : {'PASS (Khớp 100% chuẩn NIST)' if fips_pass else 'FAIL'}")

    roundtrip_pass = (recovered == plaintext)
    print(f"Kiểm tra hai chiều : {'PASS (Plaintext khôi phục trùng khớp 100%)' if roundtrip_pass else 'FAIL'}")
    print("-" * 70)


def run_text_cbc_demo(text: str, key: bytes) -> None:
    """Chạy demo mã hóa chuỗi văn bản độ dài tùy ý bằng CBC Mode + PKCS#7."""
    print("\n" + "=" * 70)
    print("DEMO 2: MÃ HÓA VĂN BẢN ĐỘ DÀI TÙY Ý VỚI PKCS#7 PADDING & CHẾ ĐỘ CBC")
    print("=" * 70)
    data = text.encode("utf-8")
    print(f"Văn bản gốc: \"{text}\" ({len(data)} bytes)")
    print(f"Khóa sử dụng: {key.hex()}")

    aes = AES(key)
    iv, ciphertext = aes.encrypt_cbc(data)
    print(f"Vector IV (ngẫu nhiên 16 bytes): {iv.hex()}")
    print(f"Bản mã CBC (đã padding PKCS#7) : {ciphertext.hex()} ({len(ciphertext)} bytes)")

    decrypted = aes.decrypt_cbc(ciphertext, iv)
    decrypted_text = decrypted.decode("utf-8")
    print(f"Văn bản sau giải mã & gỡ padding: \"{decrypted_text}\"")
    print(f"Kết quả đối chiếu nội dung: {'PASS (Nội dung trùng khớp hoàn toàn)' if decrypted_text == text else 'FAIL'}")
    print("-" * 70)


def run_zip_file_demo(key: bytes) -> None:
    """Tự động tạo một file ZIP mẫu chứa nhiều tài liệu, mã hóa và giải mã đối chiếu SHA-256."""
    print("\n" + "=" * 70)
    print("DEMO 3: MÃ HÓA VÀ GIẢI MÃ FILE ZIP ĐA NĂNG (KIỂM CHỨNG TOÀN VẸN)")
    print("=" * 70)

    work_dir = Path(__file__).resolve().parent
    sample_zip = work_dir / "sample_archive.zip"
    encrypted_file = work_dir / "sample_archive.zip.enc"
    recovered_zip = work_dir / "sample_archive_recovered.zip"

    # 1. Tạo file ZIP mẫu chứa tài liệu văn bản và dữ liệu
    print("1. Đang tạo file nén ZIP mẫu chứa 2 file dữ liệu...")
    with zipfile.ZipFile(sample_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("baocao_pbl3.txt", "Báo cáo tiến độ tuần 3 - Học phần Mạng thông tin máy tính PBL3.")
        zf.writestr("data/students.csv", "id,name,role\n1,Nguyen Thai Hoang,Student\n2,Le Truong Uyen Nhi,Student\n")

    orig_size = sample_zip.stat().st_size
    print(f"   -> Đã tạo file: {sample_zip.name} ({orig_size} bytes)")

    # 2. Mã hóa file ZIP
    print("\n2. Đang tiến hành mã hóa file ZIP bằng AES-128-CBC...")
    iv, sha256_orig = encrypt_file(sample_zip, encrypted_file, key)
    enc_size = encrypted_file.stat().st_size
    print(f"   -> File mã hóa: {encrypted_file.name} ({enc_size} bytes)")
    print(f"   -> IV khởi tạo: {iv.hex()}")
    print(f"   -> Mã băm SHA-256 file ZIP gốc : {sha256_orig}")

    # 3. Giải mã file ZIP
    print("\n3. Đang giải mã file mã hóa để khôi phục file ZIP...")
    sha256_rec = decrypt_file(encrypted_file, recovered_zip, key)
    rec_size = recovered_zip.stat().st_size
    print(f"   -> File khôi phục: {recovered_zip.name} ({rec_size} bytes)")
    print(f"   -> Mã băm SHA-256 file khôi phục: {sha256_rec}")

    # 4. Kiểm tra tính toàn vẹn và giải nén
    sha_match = (sha256_orig == sha256_rec)
    print(f"\n4. Đối chiếu mã băm toàn vẹn SHA-256: {'PASS (Trùng khớp 100% từng bit)' if sha_match else 'FAIL'}")

    print("5. Thử nghiệm mở file ZIP khôi phục và đọc nội dung:")
    with zipfile.ZipFile(recovered_zip, "r") as zf:
        for info in zf.infolist():
            print(f"   - File trong ZIP: {info.filename} ({info.file_size} bytes)")
        content = zf.read("baocao_pbl3.txt").decode("utf-8")
        print(f"   - Trích xuất nội dung 'baocao_pbl3.txt': \"{content}\"")

    print("\nKẾT LUẬN: Đã chứng minh giải thuật mã hóa/giải mã hoạt động hoàn hảo trên định dạng file ZIP đa năng!")
    print("=" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", type=hex_block, default=DEFAULT_KEY, help="Khóa 16 byte dạng hex (mặc định: FIPS C.1)")
    parser.add_argument("--password", help="Mật khẩu người dùng (dẫn xuất thành khóa 128-bit qua PBKDF2)")
    parser.add_argument("--plaintext", type=hex_block, help="Bản rõ 16 byte dạng hex")
    parser.add_argument("--text", help="Chuỗi văn bản UTF-8 bất kỳ cần mã hóa CBC")
    parser.add_argument("--trace", action="store_true", help="Hiển thị chi tiết State qua từng bước dạng ma trận 4x4")
    parser.add_argument("--demo-zip", action="store_true", help="Chạy tự động kịch bản mã hóa/giải mã file ZIP thực tế")
    parser.add_argument("--encrypt-file", help="Đường dẫn file bất kỳ cần mã hóa")
    parser.add_argument("--decrypt-file", help="Đường dẫn file mã hóa cần giải mã")
    parser.add_argument("--out", help="Đường dẫn file đầu ra khi mã hóa/giải mã file")

    args = parser.parse_args()

    try:
        if args.encrypt_file:
            out_path = args.out or (args.encrypt_file + ".enc")
            if args.password:
                iv, sha = encrypt_file(args.encrypt_file, out_path, password=args.password)
            else:
                iv, sha = encrypt_file(args.encrypt_file, out_path, key=args.key)
            print(f"Mã hóa file thành công: {args.encrypt_file} -> {out_path}")
            print(f"IV: {iv.hex()}")
            print(f"SHA-256 gốc: {sha}")
            return

        if args.decrypt_file:
            if not args.out:
                parser.error("Khi giải mã file, vui lòng chỉ định file đầu ra bằng --out <đường_dẫn>")
            if args.password:
                sha = decrypt_file(args.decrypt_file, args.out, password=args.password)
            else:
                sha = decrypt_file(args.decrypt_file, args.out, key=args.key)
            print(f"Giải mã file thành công: {args.decrypt_file} -> {args.out}")
            print(f"SHA-256 khôi phục: {sha}")
            return

        # Với các chế độ demo trên bộ nhớ (--demo-zip, --text, single block)
        if args.password:
            key, salt = derive_key(args.password)
            print(f'[Key Derivation] Dẫn xuất khóa từ mật khẩu "{args.password}":')
            print(f"  Salt: {salt.hex()}")
            print(f"  Key : {key.hex()}\n")
        else:
            key = args.key

        if args.demo_zip:
            run_zip_file_demo(key)
        elif args.text is not None:
            run_text_cbc_demo(args.text, key)
        else:
            plaintext = args.plaintext if args.plaintext is not None else bytes.fromhex(DEFAULT_PLAINTEXT)
            run_single_block_demo(plaintext, key, args.trace)

    except ValueError as err:
        print(f"[LỖI DỮ LIỆU / XÁC THỰC]: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
