"""Bộ kiểm thử tự động toàn diện AES-128 (Tuần 3):
- Đối chiếu vector chuẩn NIST FIPS 197 C.1 và 4 khối NIST Core.
- Kiểm thử cơ chế đệm PKCS#7 (các trường hợp biên: 0 byte, 15 byte, 16 byte, padding lỗi).
- Kiểm thử cơ chế dẫn xuất khóa PBKDF2-HMAC-SHA256 và sinh khóa CSPRNG.
- Kiểm thử chế độ CBC đa khối và tính nghịch đảo 2 chiều.
- Kiểm thử mã hóa/giải mã file nhị phân và file ZIP thực tế với mã băm SHA-256.

Chạy: python -m unittest -v test_aes.py
"""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from aes import (
    AES,
    decrypt_file,
    derive_key,
    encrypt_file,
    generate_key,
    pad,
    unpad,
)

FIPS_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


class AESWeek3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.aes = AES(FIPS_KEY)

    def test_fips_197_ciphertext(self) -> None:
        """Kiểm tra mã hóa khối đơn khớp chuẩn NIST FIPS 197 Phụ lục C.1."""
        ciphertext = self.aes.encrypt_block(FIPS_PLAINTEXT)
        self.assertEqual(ciphertext, FIPS_CIPHERTEXT)

    def test_fips_197_plaintext(self) -> None:
        """Kiểm tra giải mã khối đơn khôi phục chính xác bản rõ FIPS 197 C.1."""
        recovered = self.aes.decrypt_block(FIPS_CIPHERTEXT)
        self.assertEqual(recovered, FIPS_PLAINTEXT)

    def test_nist_core_blocks(self) -> None:
        """Kiểm tra 4 vector chuẩn từ tài liệu NIST AES_Core128."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        core_aes = AES(key)
        vectors = (
            ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
            ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
            ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
            ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
        )
        for p_hex, expected_c_hex in vectors:
            with self.subTest(plaintext=p_hex):
                c = core_aes.encrypt_block(bytes.fromhex(p_hex))
                self.assertEqual(c.hex(), expected_c_hex)
                rec = core_aes.decrypt_block(c)
                self.assertEqual(rec.hex(), p_hex)

    def test_key_expansion_structure(self) -> None:
        """Kiểm tra expand_key sinh đủ 11 ma trận khóa vòng 4x4."""
        self.assertEqual(len(self.aes.round_keys), 11)
        for rk in self.aes.round_keys:
            self.assertEqual(len(rk), 4)
            for col in rk:
                self.assertEqual(len(col), 4)

    def test_pkcs7_padding_roundtrip(self) -> None:
        """Kiểm tra đệm và gỡ đệm PKCS#7 với các độ dài dữ liệu khác nhau."""
        test_lengths = (0, 1, 2, 15, 16, 17, 31, 32, 100, 255)
        for length in test_lengths:
            with self.subTest(length=length):
                original = os.urandom(length)
                padded = pad(original, 16)
                self.assertEqual(len(padded) % 16, 0)
                self.assertTrue(len(padded) > len(original))
                unpadded = unpad(padded, 16)
                self.assertEqual(unpadded, original)

    def test_pkcs7_corrupt_padding_rejection(self) -> None:
        """Kiểm tra unpad từ chối dữ liệu có byte đệm bị hỏng."""
        data = b"Hello World 1234"
        padded = bytearray(pad(data, 16))
        padded[-1] ^= 0xFF  # Làm sai lệch byte đệm cuối cùng
        with self.assertRaises(ValueError):
            unpad(bytes(padded), 16)

        with self.assertRaises(ValueError):
            unpad(b"Not 16 bytes", 16)

    def test_key_generation_and_derivation(self) -> None:
        """Kiểm tra cơ chế sinh khóa ngẫu nhiên và dẫn xuất khóa từ mật khẩu."""
        k1 = generate_key(16)
        k2 = generate_key(16)
        self.assertEqual(len(k1), 16)
        self.assertEqual(len(k2), 16)
        self.assertNotEqual(k1, k2)

        pwd = "BaoCaoPBL3MatKhau@2026"
        salt = bytes.fromhex("11223344556677889900aabbccddeeff")
        dk1, _ = derive_key(pwd, salt=salt, iterations=10_000)
        dk2, _ = derive_key(pwd, salt=salt, iterations=10_000)
        self.assertEqual(len(dk1), 16)
        self.assertEqual(dk1, dk2)  # Tính tiền định (deterministic) với cùng salt

    def test_cbc_mode_arbitrary_length(self) -> None:
        """Kiểm tra chế độ CBC mã hóa và giải mã chuỗi văn bản UTF-8 ngẫu nhiên."""
        messages = (
            b"",
            b"A",
            b"Exact 16 bytes!!",
            b"Thirty-two bytes long message!!!",
            "Tiếng Việt có dấu: Khóa luận PBL3 Mạng máy tính và An toàn thông tin.".encode("utf-8"),
            os.urandom(1024),  # 1 KB nhị phân
        )
        for msg in messages:
            with self.subTest(msg_len=len(msg)):
                iv, ciphertext = self.aes.encrypt_cbc(msg)
                self.assertEqual(len(iv), 16)
                self.assertEqual(len(ciphertext) % 16, 0)
                decrypted = self.aes.decrypt_cbc(ciphertext, iv)
                self.assertEqual(decrypted, msg)

    def test_binary_file_encryption_sha256(self) -> None:
        """Kiểm tra mã hóa và giải mã file nhị phân ngẫu nhiên (đối chiếu SHA-256)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            orig_file = temp_path / "original.bin"
            enc_file = temp_path / "encrypted.bin"
            dec_file = temp_path / "decrypted.bin"

            # Tạo file nhị phân 10.500 byte ngẫu nhiên (kích thước lẻ không chia hết cho 16)
            data = os.urandom(10_500)
            orig_file.write_bytes(data)

            key = generate_key(16)
            iv, sha_orig = encrypt_file(orig_file, enc_file, key)
            sha_dec = decrypt_file(enc_file, dec_file, key)

            self.assertEqual(sha_orig, hashlib.sha256(data).hexdigest())
            self.assertEqual(sha_orig, sha_dec)
            self.assertEqual(dec_file.read_bytes(), data)

    def test_zip_file_encryption_integrity(self) -> None:
        """Kiểm tra mã hóa và giải mã file ZIP thực tế, giải nén xác nhận toàn vẹn."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            zip_orig = temp_path / "document.zip"
            zip_enc = temp_path / "document.zip.enc"
            zip_dec = temp_path / "document_restored.zip"

            # 1. Tạo file ZIP chứa 2 tệp tin
            with zipfile.ZipFile(zip_orig, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("info.txt", "Tài liệu môn học PBL3 - Mạng thông tin máy tính.")
                zf.writestr("sub/table.csv", "A,B,C\n1,2,3\n4,5,6\n")

            sha_original = hashlib.sha256(zip_orig.read_bytes()).hexdigest()

            # 2. Mã hóa & Giải mã
            key = generate_key(16)
            encrypt_file(zip_orig, zip_enc, key)
            sha_restored = decrypt_file(zip_enc, zip_dec, key)

            # 3. Kiểm tra tính toàn vẹn
            self.assertEqual(sha_original, sha_restored)

            # 4. Mở file ZIP đã giải mã và đọc kiểm tra
            with zipfile.ZipFile(zip_dec, "r") as zf:
                self.assertIn("info.txt", zf.namelist())
                self.assertIn("sub/table.csv", zf.namelist())
                content = zf.read("info.txt").decode("utf-8")
                self.assertEqual(content, "Tài liệu môn học PBL3 - Mạng thông tin máy tính.")

    def test_nist_sp800_38a_cbc_vectors(self) -> None:
        """Đối chiếu trực tiếp chế độ CBC với 4 khối Vector chuẩn NIST SP 800-38A Phụ lục F.2.1."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext_4_blocks = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        expected_cbc_4_blocks = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        )
        cbc_aes = AES(key)
        _, ciphertext = cbc_aes.encrypt_cbc(plaintext_4_blocks, iv=iv)
        # Do encrypt_cbc tự động thêm 1 block PKCS#7 (16 byte 0x10) ở cuối dữ liệu 64 byte,
        # 64 byte đầu tiên của ciphertext phải khớp tuyệt đối 4 khối của NIST SP 800-38A:
        self.assertEqual(ciphertext[:64], expected_cbc_4_blocks)
        recovered = cbc_aes.decrypt_cbc(ciphertext, iv=iv)
        self.assertEqual(recovered, plaintext_4_blocks)

    def test_file_encryption_with_password(self) -> None:
        """Kiểm tra mã hóa và giải mã file bằng mật khẩu (tự động lưu và khôi phục Salt)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            orig_file = temp_path / "secret.txt"
            enc_file = temp_path / "secret.txt.enc"
            dec_file = temp_path / "secret_recovered.txt"

            raw_data = "Dữ liệu mật kiểm thử PBKDF2 + Salt trong file".encode("utf-8")
            orig_file.write_bytes(raw_data)

            _, sha_orig = encrypt_file(orig_file, enc_file, password="MySecretPass@2026")
            sha_dec = decrypt_file(enc_file, dec_file, password="MySecretPass@2026")

            self.assertEqual(sha_orig, sha_dec)
            self.assertEqual(dec_file.read_bytes(), raw_data)

            # Kiểm tra nhập sai mật khẩu phải báo lỗi ValueError
            with self.assertRaises(ValueError):
                decrypt_file(enc_file, dec_file, password="WrongPassword123")

    def test_invalid_parameters_raise(self) -> None:
        """Kiểm tra ném ngoại lệ khi truyền tham số sai kích thước."""
        with self.assertRaises(ValueError):
            AES(b"short_key")
        with self.assertRaises(TypeError):
            AES("string_key_not_bytes")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            self.aes.encrypt_block(b"short_block")
        with self.assertRaises(ValueError):
            self.aes.decrypt_block(b"short_block")


if __name__ == "__main__":
    unittest.main()
