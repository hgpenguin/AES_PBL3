"""AES-128 thuần Python với CBC, đệm PKCS#7 và dẫn xuất khóa PBKDF2.

Lõi AES tham khảo boppreh/aes (MIT) và The Design of Rijndael.
Xử lý tệp đọc toàn bộ dữ liệu vào RAM. CBC chỉ cung cấp tính bí mật.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path

S_BOX: tuple[int, ...] = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX: tuple[int, ...] = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

R_CON: tuple[int, ...] = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

# Tên cũ được giữ để tương thích.
s_box = S_BOX
inv_s_box = INV_S_BOX
r_con = R_CON

TraceCallback = Callable[[int, str, bytes], None]


def bytes2matrix(text: bytes) -> list[list[int]]:
    """Gom từng 4 byte thành một cột. Truy cập state theo state[cột][hàng]."""
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix: list[list[int]]) -> bytes:
    return bytes(b for col in matrix for b in col)


def xtime(a: int) -> int:
    """Nhân một byte với 0x02 trong GF(2^8)."""
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def sub_bytes(s: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            s[i][j] = S_BOX[s[i][j]]


def shift_rows(s: list[list[int]]) -> None:
    """Dịch vòng trái từng hàng theo chỉ số hàng."""
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def mix_single_column(a: list[int]) -> None:
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s: list[list[int]]) -> None:
    for i in range(4):
        mix_single_column(s[i])


def add_round_key(s: list[list[int]], k: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def inv_sub_bytes(s: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            s[i][j] = INV_S_BOX[s[i][j]]


def inv_shift_rows(s: list[list[int]]) -> None:
    """Dịch vòng phải từng hàng theo chỉ số hàng."""
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def inv_mix_columns(s: list[list[int]]) -> None:
    """Hiệu chỉnh từng cột rồi áp dụng lại MixColumns."""
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v
    mix_columns(s)


def pad(data: bytes, block_size: int = 16) -> bytes:
    """Thêm đệm PKCS#7."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes, block_size: int = 16) -> bytes:
    """Kiểm tra và gỡ đệm PKCS#7."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Dữ liệu cần unpad không hợp lệ (không phải bội số của block_size)")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Padding PKCS#7 không hợp lệ: giá trị byte đệm ngoài phạm vi 1-16")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Padding PKCS#7 bị hỏng hoặc sai giá trị kiểm tra")
    return data[:-padding_len]


def generate_key(length: int = 16) -> bytes:
    return os.urandom(length)


def derive_key(
    password: str | bytes,
    salt: bytes | None = None,
    iterations: int = 100_000,
) -> tuple[bytes, bytes]:
    """Trả về (key, salt) từ PBKDF2-HMAC-SHA256."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=16)
    return key, salt


class AES:
    """Bộ mã hóa và giải mã AES-128 trên ma trận 2D."""

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Khóa phải là kiểu bytes hoặc bytearray")
        if len(key) != 16:
            raise ValueError("AES-128 yêu cầu khóa có độ dài chính xác 16 byte (128 bit)")
        self.key = bytes(key)
        self.round_keys = self.expand_key(self.key)

    def expand_key(self, key: bytes) -> list[list[list[int]]]:
        """Mở rộng khóa thành 11 khóa vòng (K0 đến K10)."""
        words = bytes2matrix(key)
        for i in range(4, 44):
            word = list(words[i - 1])
            if i % 4 == 0:
                word = word[1:] + word[:1]  # RotWord
                word = [S_BOX[b] for b in word]  # SubWord
                word[0] ^= R_CON[i // 4]
            word = [a ^ b for a, b in zip(word, words[i - 4])]
            words.append(word)
        return [words[i:i + 4] for i in range(0, 44, 4)]

    def encrypt_block(self, plaintext: bytes, trace: TraceCallback | None = None) -> bytes:
        """Mã hóa một khối 16 byte, có thể theo dõi từng bước qua trace."""
        if len(plaintext) != 16:
            raise ValueError("Block bản rõ phải có độ dài đúng 16 byte")
        state = bytes2matrix(plaintext)

        def record(round_no: int, step: str) -> None:
            if trace:
                trace(round_no, step, matrix2bytes(state))

        record(0, "Input")
        add_round_key(state, self.round_keys[0])
        record(0, "AddRoundKey")

        for round_no in range(1, 11):
            sub_bytes(state)
            record(round_no, "SubBytes")
            shift_rows(state)
            record(round_no, "ShiftRows")
            if round_no < 10:
                mix_columns(state)
                record(round_no, "MixColumns")
            add_round_key(state, self.round_keys[round_no])
            record(round_no, "AddRoundKey")

        return matrix2bytes(state)

    def decrypt_block(self, ciphertext: bytes, trace: TraceCallback | None = None) -> bytes:
        """Giải mã một khối 16 byte, có thể theo dõi từng bước qua trace."""
        if len(ciphertext) != 16:
            raise ValueError("Block bản mã phải có độ dài đúng 16 byte")
        state = bytes2matrix(ciphertext)

        def record(round_no: int, step: str) -> None:
            if trace:
                trace(round_no, step, matrix2bytes(state))

        record(0, "Input")
        add_round_key(state, self.round_keys[10])
        record(0, "AddRoundKey")

        for round_no in range(1, 11):
            inv_shift_rows(state)
            record(round_no, "InvShiftRows")
            inv_sub_bytes(state)
            record(round_no, "InvSubBytes")
            add_round_key(state, self.round_keys[10 - round_no])
            record(round_no, "AddRoundKey")
            if round_no < 10:
                inv_mix_columns(state)
                record(round_no, "InvMixColumns")

        return matrix2bytes(state)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
        """Mã hóa CBC với đệm PKCS#7. Trả về (iv, ciphertext)."""
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("Vector khởi tạo IV phải có độ dài đúng 16 byte")

        padded = pad(plaintext)
        ciphertext_blocks: list[bytes] = []
        prev = iv

        for offset in range(0, len(padded), 16):
            block = padded[offset:offset + 16]
            xored = bytes(a ^ b for a, b in zip(block, prev))
            prev = self.encrypt_block(xored)
            ciphertext_blocks.append(prev)

        return iv, b"".join(ciphertext_blocks)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """Giải mã CBC và gỡ đệm PKCS#7."""
        if len(iv) != 16:
            raise ValueError("Vector khởi tạo IV phải có độ dài đúng 16 byte")
        if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext CBC phải có độ dài là bội số của 16 byte")

        plaintext_blocks: list[bytes] = []
        prev = iv

        for offset in range(0, len(ciphertext), 16):
            block = ciphertext[offset:offset + 16]
            decrypted = self.decrypt_block(block)
            plain_block = bytes(a ^ b for a, b in zip(decrypted, prev))
            plaintext_blocks.append(plain_block)
            prev = block

        return unpad(b"".join(plaintext_blocks))


PWD_MAGIC = b"AES3PWD\x00"


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes | None = None,
    iv: bytes | None = None,
    password: str | bytes | None = None,
) -> tuple[bytes, str]:
    """Mã hóa tệp và trả về (iv, SHA-256 của tệp gốc).

    Với khóa trực tiếp, tệp chứa IV + bản mã CBC.
    Với mật khẩu, tệp chứa PWD_MAGIC + salt + IV + bản mã CBC.
    """
    if key is not None and password is not None:
        raise ValueError("Chỉ truyền một trong hai tham số: `key` hoặc `password`")
    if key is None and password is None:
        raise ValueError("Cần cung cấp khóa `key` (16 byte) hoặc `password` để mã hóa file")

    data = Path(input_path).read_bytes()
    sha256_orig = hashlib.sha256(data).hexdigest()

    header = b""
    if password is not None:
        key, salt = derive_key(password)
        header = PWD_MAGIC + salt

    assert key is not None
    used_iv, ciphertext = AES(key).encrypt_cbc(data, iv=iv)
    Path(output_path).write_bytes(header + used_iv + ciphertext)
    return used_iv, sha256_orig


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes | None = None,
    password: str | bytes | None = None,
) -> str:
    """Giải mã tệp và trả về SHA-256 của tệp khôi phục."""
    payload = Path(input_path).read_bytes()

    iv_start = 0
    if payload.startswith(PWD_MAGIC):
        salt_start = len(PWD_MAGIC)
        iv_start = salt_start + 16
        if len(payload) < iv_start + 32:
            raise ValueError("File mã hóa bằng mật khẩu không hợp lệ hoặc bị cắt cụt")
        if password is None:
            raise ValueError(
                "File này được mã hóa bằng mật khẩu, vui lòng truyền tham số `password` khi giải mã"
            )
        salt = payload[salt_start:iv_start]
        key, _ = derive_key(password, salt=salt)
    else:
        if len(payload) < 32:
            raise ValueError("File mã hóa không hợp lệ hoặc quá ngắn (thiếu IV hoặc dữ liệu)")
        if password is not None and key is None:
            raise ValueError(
                "File này được mã hóa bằng khóa trực tiếp, "
                "vui lòng truyền tham số `key` khi giải mã"
            )
        if key is None:
            raise ValueError("Cần cung cấp khóa `key` (16 byte) để giải mã file")

    iv_end = iv_start + 16
    iv = payload[iv_start:iv_end]
    plaintext = AES(key).decrypt_cbc(payload[iv_end:], iv)
    Path(output_path).write_bytes(plaintext)
    return hashlib.sha256(plaintext).hexdigest()
