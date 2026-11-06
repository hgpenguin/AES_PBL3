"""Kiểm thử AES-128, CBC và mã hóa tệp."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from aes import AES, decrypt_file, derive_key, encrypt_file, generate_key, pad, unpad

FIPS_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


class AESWeek3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.aes = AES(FIPS_KEY)

    def test_fips_197_ciphertext(self) -> None:
        self.assertEqual(self.aes.encrypt_block(FIPS_PLAINTEXT), FIPS_CIPHERTEXT)

    def test_fips_197_plaintext(self) -> None:
        self.assertEqual(self.aes.decrypt_block(FIPS_CIPHERTEXT), FIPS_PLAINTEXT)

    def test_nist_core_blocks(self) -> None:
        aes = AES(NIST_KEY)
        vectors = (
            ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
            ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
            ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
            ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
        )
        for plaintext_hex, expected_hex in vectors:
            with self.subTest(plaintext=plaintext_hex):
                plaintext = bytes.fromhex(plaintext_hex)
                ciphertext = aes.encrypt_block(plaintext)
                self.assertEqual(ciphertext.hex(), expected_hex)
                self.assertEqual(aes.decrypt_block(ciphertext), plaintext)

    def test_key_expansion_structure(self) -> None:
        self.assertEqual(len(self.aes.round_keys), 11)
        for round_key in self.aes.round_keys:
            self.assertEqual(len(round_key), 4)
            for column in round_key:
                self.assertEqual(len(column), 4)

    def test_pkcs7_padding_roundtrip(self) -> None:
        for length in (0, 1, 2, 15, 16, 17, 31, 32, 100, 255):
            with self.subTest(length=length):
                original = os.urandom(length)
                padded = pad(original, 16)
                self.assertEqual(len(padded) % 16, 0)
                self.assertGreater(len(padded), len(original))
                self.assertEqual(unpad(padded, 16), original)

    def test_pkcs7_corrupt_padding_rejection(self) -> None:
        padded = bytearray(pad(b"Hello World 1234", 16))
        padded[-1] = 0xFF
        with self.assertRaises(ValueError):
            unpad(bytes(padded), 16)

        with self.assertRaises(ValueError):
            unpad(b"Not 16 bytes", 16)

    def test_key_generation_and_derivation(self) -> None:
        first_key = generate_key(16)
        second_key = generate_key(16)
        self.assertEqual(len(first_key), 16)
        self.assertEqual(len(second_key), 16)
        self.assertNotEqual(first_key, second_key)

        password = "BaoCaoPBL3MatKhau@2026"
        salt = bytes.fromhex("11223344556677889900aabbccddeeff")
        derived_key, _ = derive_key(password, salt=salt, iterations=10_000)
        repeated_key, _ = derive_key(password, salt=salt, iterations=10_000)
        self.assertEqual(len(derived_key), 16)
        self.assertEqual(derived_key, repeated_key)

    def test_cbc_mode_arbitrary_length(self) -> None:
        messages = (
            b"",
            b"A",
            b"Exact 16 bytes!!",
            b"Thirty-two bytes long message!!!",
            "Tiếng Việt có dấu: Khóa luận PBL3 Mạng máy tính và An toàn thông tin.".encode("utf-8"),
            os.urandom(1024),
        )
        for msg in messages:
            with self.subTest(msg_len=len(msg)):
                iv, ciphertext = self.aes.encrypt_cbc(msg)
                self.assertEqual(len(iv), 16)
                self.assertEqual(len(ciphertext) % 16, 0)
                self.assertEqual(self.aes.decrypt_cbc(ciphertext, iv), msg)

    def test_binary_file_encryption_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            orig_file = temp_path / "original.bin"
            enc_file = temp_path / "encrypted.bin"
            dec_file = temp_path / "decrypted.bin"

            data = os.urandom(10_500)
            orig_file.write_bytes(data)

            key = generate_key(16)
            _, sha_orig = encrypt_file(orig_file, enc_file, key)
            sha_dec = decrypt_file(enc_file, dec_file, key)

            self.assertEqual(sha_orig, hashlib.sha256(data).hexdigest())
            self.assertEqual(sha_orig, sha_dec)
            self.assertEqual(dec_file.read_bytes(), data)

    def test_zip_file_encryption_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            zip_orig = temp_path / "document.zip"
            zip_enc = temp_path / "document.zip.enc"
            zip_dec = temp_path / "document_restored.zip"

            text = "Tài liệu môn học PBL3 - Mạng thông tin máy tính."
            with zipfile.ZipFile(zip_orig, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("info.txt", text)
                archive.writestr("sub/table.csv", "A,B,C\n1,2,3\n4,5,6\n")

            sha_original = hashlib.sha256(zip_orig.read_bytes()).hexdigest()

            key = generate_key(16)
            encrypt_file(zip_orig, zip_enc, key)
            sha_restored = decrypt_file(zip_enc, zip_dec, key)

            self.assertEqual(sha_original, sha_restored)

            with zipfile.ZipFile(zip_dec) as archive:
                self.assertIn("sub/table.csv", archive.namelist())
                self.assertEqual(archive.read("info.txt").decode("utf-8"), text)

    def test_nist_sp800_38a_cbc_vectors(self) -> None:
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
        aes = AES(NIST_KEY)
        _, ciphertext = aes.encrypt_cbc(plaintext_4_blocks, iv=iv)
        # Vector NIST F.2.1 chưa có khối đệm PKCS#7.
        self.assertEqual(ciphertext[:len(expected_cbc_4_blocks)], expected_cbc_4_blocks)
        self.assertEqual(aes.decrypt_cbc(ciphertext, iv), plaintext_4_blocks)

    def test_file_encryption_with_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            orig_file = temp_path / "secret.txt"
            enc_file = temp_path / "secret.txt.enc"
            dec_file = temp_path / "secret_recovered.txt"

            raw_data = "Dữ liệu mật kiểm thử PBKDF2 + Salt trong file".encode("utf-8")
            orig_file.write_bytes(raw_data)

            password = "MySecretPass@2026"
            # Cố định salt và IV để ca sai mật khẩu cho kết quả lặp lại.
            with patch("aes.os.urandom", return_value=bytes(16)):
                _, sha_orig = encrypt_file(orig_file, enc_file, password=password)
            sha_dec = decrypt_file(enc_file, dec_file, password=password)

            self.assertEqual(sha_orig, sha_dec)
            self.assertEqual(dec_file.read_bytes(), raw_data)

            with self.assertRaises(ValueError):
                decrypt_file(enc_file, dec_file, password="WrongPassword123")

    def test_invalid_parameters_raise(self) -> None:
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
