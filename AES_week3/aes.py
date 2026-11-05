"""Lõi thuật toán AES-128 thuần Python theo kiến trúc Ma trận 2D và Hướng đối tượng (OOP).

Phiên bản Tuần 3:
- Kiến trúc State ma trận 4x4 (list of lists of ints) trực quan, bám sát sách 'The Design of Rijndael'.
- Đóng gói đầy đủ trong `class AES` (Key Expansion, encrypt_block, decrypt_block).
- Mở rộng Tuần 3:
  + Tự động sinh khóa ngẫu nhiên CSPRNG (os.urandom) và dẫn xuất khóa PBKDF2-HMAC-SHA256 từ mật khẩu.
  + Cơ chế đệm và giải đệm PKCS#7 (pad, unpad).
  + Chế độ hoạt động CBC (Cipher Block Chaining) với Vector khởi tạo IV ngẫu nhiên.
  + Mô-đun mã hóa và giải mã File / ZIP đa năng kèm kiểm tra toàn vẹn mã băm SHA-256.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path

# --- CÁC HẰNG SỐ CHUẨN CỦA AES-128 (FIPS 197) ---

s_box: tuple[int, ...] = (
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

inv_s_box: tuple[int, ...] = (
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

r_con: tuple[int, ...] = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

TraceCallback = Callable[[int, str, bytes], None]


# --- CÁC HÀM TIỆN ÍCH CHUYỂN ĐỔI MA TRẬN 2D VÀ TOÁN HỌC GF(2^8) ---

def bytes2matrix(text: bytes) -> list[list[int]]:
    """Chuyển đổi chuỗi 16 byte thành ma trận 4x4 (4 cột, mỗi cột 4 byte)."""
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix: list[list[int]]) -> bytes:
    """Chuyển đổi ma trận 4x4 trở lại thành chuỗi 16 byte theo thứ tự cột."""
    return bytes(sum(matrix, []))


def xtime(a: int) -> int:
    """Nhân một byte với {02} trong GF(2^8), modulo x^8 + x^4 + x^3 + x + 1."""
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


# --- 4 PHÉP BIẾN ĐỔI THUẬN TRÊN MA TRẬN 2D (ENCRYPTION) ---

def sub_bytes(s: list[list[int]]) -> None:
    """Thay thế phi tuyến từng byte qua bảng S-box."""
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def shift_rows(s: list[list[int]]) -> None:
    """Dịch vòng trái các hàng: hàng 1 dịch 1, hàng 2 dịch 2, hàng 3 dịch 3."""
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def mix_single_column(a: list[int]) -> None:
    """Biến đổi đại số Rijndael nhanh trên một cột 4 byte trong GF(2^8)."""
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s: list[list[int]]) -> None:
    """Khuếch tán dữ liệu bằng phép nhân ma trận trên cả 4 cột."""
    for i in range(4):
        mix_single_column(s[i])


def add_round_key(s: list[list[int]], k: list[list[int]]) -> None:
    """XOR từng byte của State với ma trận khóa vòng tương ứng."""
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


# --- 4 PHÉP BIẾN ĐỔI NGHỊCH TRÊN MA TRẬN 2D (DECRYPTION) ---

def inv_sub_bytes(s: list[list[int]]) -> None:
    """Thay thế nghịch đảo từng byte qua bảng Inv S-box."""
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def inv_shift_rows(s: list[list[int]]) -> None:
    """Dịch vòng phải các hàng: hàng 1 dịch 1, hàng 2 dịch 2, hàng 3 dịch 3."""
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def inv_mix_columns(s: list[list[int]]) -> None:
    """Nghịch đảo MixColumns theo công thức tối ưu của sách The Design of Rijndael."""
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v
    mix_columns(s)


# --- CƠ CHẾ ĐỆM DỮ LIỆU CHUẨN PKCS#7 (TUẦN 3) ---

def pad(data: bytes, block_size: int = 16) -> bytes:
    """Thêm byte đệm PKCS#7 để độ dài dữ liệu là bội số của block_size (16 byte)."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes, block_size: int = 16) -> bytes:
    """Gỡ bỏ và xác thực byte đệm PKCS#7. Báo lỗi nếu padding bị sai."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Dữ liệu cần unpad không hợp lệ (không phải bội số của block_size)")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Padding PKCS#7 không hợp lệ: giá trị byte đệm ngoài phạm vi 1-16")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Padding PKCS#7 bị hỏng hoặc sai giá trị kiểm tra")
    return data[:-padding_len]


# --- CƠ CHẾ TỰ ĐỘNG SINH KHÓA VÀ DẪN XUẤT KHÓA (TUẦN 3) ---

def generate_key(length: int = 16) -> bytes:
    """Sinh khóa ngẫu nhiên an toàn bằng CSPRNG của hệ điều hành."""
    return os.urandom(length)


def derive_key(
    password: str | bytes,
    salt: bytes | None = None,
    iterations: int = 100_000,
) -> tuple[bytes, bytes]:
    """Dẫn xuất khóa AES-128 từ mật khẩu bất kỳ qua PBKDF2-HMAC-SHA256. Trả về (key, salt)."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=16)
    return key, salt


# --- LỚP CHÍNH: CLASS AES-128 ---

class AES:
    """Bộ mã hóa và giải mã AES-128 thuần Python trên ma trận 2D."""

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Khóa phải là kiểu bytes hoặc bytearray")
        if len(key) != 16:
            raise ValueError("AES-128 yêu cầu khóa có độ dài chính xác 16 byte (128 bit)")
        self.key = bytes(key)
        self.round_keys = self.expand_key(self.key)

    def expand_key(self, key: bytes) -> list[list[list[int]]]:
        """Mở rộng khóa 16 byte thành 11 ma trận khóa vòng 4x4 (K0 đến K10)."""
        words = bytes2matrix(key)
        for i in range(4, 44):
            word = list(words[i - 1])
            if i % 4 == 0:
                word = word[1:] + word[:1]  # RotWord
                word = [s_box[b] for b in word]  # SubWord
                word[0] ^= r_con[i // 4]  # XOR Rcon
            word = [a ^ b for a, b in zip(word, words[i - 4])]
            words.append(word)
        return [words[i:i + 4] for i in range(0, 44, 4)]

    def encrypt_block(self, plaintext: bytes, trace: TraceCallback | None = None) -> bytes:
        """Mã hóa một khối 16 byte; hỗ trợ trace từng bước biến đổi chi tiết."""
        if len(plaintext) != 16:
            raise ValueError("Block bản rõ phải có độ dài đúng 16 byte")
        state = bytes2matrix(plaintext)

        def record(round_no: int, step: str) -> None:
            if trace:
                trace(round_no, step, matrix2bytes(state))

        record(0, "Input")
        add_round_key(state, self.round_keys[0])
        record(0, "AddRoundKey")

        for round_no in range(1, 10):
            sub_bytes(state)
            record(round_no, "SubBytes")
            shift_rows(state)
            record(round_no, "ShiftRows")
            mix_columns(state)
            record(round_no, "MixColumns")
            add_round_key(state, self.round_keys[round_no])
            record(round_no, "AddRoundKey")

        # Vòng 10 (bỏ qua MixColumns)
        sub_bytes(state)
        record(10, "SubBytes")
        shift_rows(state)
        record(10, "ShiftRows")
        add_round_key(state, self.round_keys[10])
        record(10, "AddRoundKey")

        return matrix2bytes(state)

    def decrypt_block(self, ciphertext: bytes, trace: TraceCallback | None = None) -> bytes:
        """Giải mã một khối 16 byte theo chuẩn INVCIPHER (FIPS 197)."""
        if len(ciphertext) != 16:
            raise ValueError("Block bản mã phải có độ dài đúng 16 byte")
        state = bytes2matrix(ciphertext)

        def record(round_no: int, step: str) -> None:
            if trace:
                trace(round_no, step, matrix2bytes(state))

        record(0, "Input")
        add_round_key(state, self.round_keys[10])
        record(0, "AddRoundKey")

        for round_no in range(1, 10):
            inv_shift_rows(state)
            record(round_no, "InvShiftRows")
            inv_sub_bytes(state)
            record(round_no, "InvSubBytes")
            add_round_key(state, self.round_keys[10 - round_no])
            record(round_no, "AddRoundKey")
            inv_mix_columns(state)
            record(round_no, "InvMixColumns")

        # Vòng cuối đảo (bỏ qua InvMixColumns)
        inv_shift_rows(state)
        record(10, "InvShiftRows")
        inv_sub_bytes(state)
        record(10, "InvSubBytes")
        add_round_key(state, self.round_keys[0])
        record(10, "AddRoundKey")

        return matrix2bytes(state)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
        """Mã hóa chuỗi byte độ dài bất kỳ bằng chế độ CBC kèm đệm PKCS#7. Trả về (iv, ciphertext)."""
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("Vector khởi tạo IV phải có độ dài đúng 16 byte")

        padded = pad(plaintext, 16)
        blocks = [padded[i:i + 16] for i in range(0, len(padded), 16)]
        ciphertext_blocks: list[bytes] = []
        prev = iv

        for block in blocks:
            xored = bytes(a ^ b for a, b in zip(block, prev))
            encrypted = self.encrypt_block(xored)
            ciphertext_blocks.append(encrypted)
            prev = encrypted

        return iv, b"".join(ciphertext_blocks)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """Giải mã ciphertext CBC và gỡ đệm PKCS#7 để khôi phục plaintext."""
        if len(iv) != 16:
            raise ValueError("Vector khởi tạo IV phải có độ dài đúng 16 byte")
        if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext CBC phải có độ dài là bội số của 16 byte")

        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
        plaintext_blocks: list[bytes] = []
        prev = iv

        for block in blocks:
            decrypted = self.decrypt_block(block)
            plain_block = bytes(a ^ b for a, b in zip(decrypted, prev))
            plaintext_blocks.append(plain_block)
            prev = block

        padded = b"".join(plaintext_blocks)
        return unpad(padded, 16)


# --- MÔ-ĐUN MÃ HÓA VÀ GIẢI MÃ FILE / ZIP ĐA NĂNG (TUẦN 3) ---

PWD_MAGIC = b"AES3PWD\x00"  # 8 byte nhận diện file được mã hóa bằng mật khẩu (kèm Salt)


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes | None = None,
    iv: bytes | None = None,
    password: str | bytes | None = None,
) -> tuple[bytes, str]:
    """Mã hóa file bất kỳ (text, binary, zip, pdf) bằng AES-128-CBC.

    - Nếu truyền `key` (16 byte): Định dạng đầu ra là [16B IV] + [Ciphertext CBC].
    - Nếu truyền `password`: Tự động sinh Salt (16B), dẫn xuất khóa PBKDF2 và lưu
      theo cấu trúc [8B Magic] + [16B Salt] + [16B IV] + [Ciphertext CBC] để khi giải
      mã có thể tự động khôi phục đúng khóa từ mật khẩu.
    Trả về (iv, sha256_file_gốc).
    """
    inp = Path(input_path)
    out = Path(output_path)
    data = inp.read_bytes()
    sha256_orig = hashlib.sha256(data).hexdigest()

    if password is not None:
        derived_key, salt = derive_key(password)
        aes = AES(derived_key)
        used_iv, ciphertext = aes.encrypt_cbc(data, iv=iv)
        out.write_bytes(PWD_MAGIC + salt + used_iv + ciphertext)
        return used_iv, sha256_orig

    if key is None:
        raise ValueError("Cần cung cấp khóa `key` (16 byte) hoặc `password` để mã hóa file")

    aes = AES(key)
    used_iv, ciphertext = aes.encrypt_cbc(data, iv=iv)
    out.write_bytes(used_iv + ciphertext)
    return used_iv, sha256_orig


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes | None = None,
    password: str | bytes | None = None,
) -> str:
    """Giải mã file AES-128-CBC và khôi phục file gốc nguyên vẹn.

    Tự động trích xuất Salt nếu file được mã hóa bằng mật khẩu (PBKDF2).
    Trả về sha256_file_khôi_phục để đối chiếu toàn vẹn.
    """
    inp = Path(input_path)
    out = Path(output_path)
    payload = inp.read_bytes()

    if payload.startswith(PWD_MAGIC):
        if len(payload) < 8 + 16 + 16 + 16:
            raise ValueError("File mã hóa bằng mật khẩu không hợp lệ hoặc bị cắt cụt")
        if password is None:
            raise ValueError("File này được mã hóa bằng mật khẩu, vui lòng truyền --password khi giải mã")
        salt = payload[8:24]
        iv = payload[24:40]
        ciphertext = payload[40:]
        derived_key, _ = derive_key(password, salt=salt)
        aes = AES(derived_key)
    else:
        if len(payload) < 32:
            raise ValueError("File mã hóa không hợp lệ hoặc quá ngắn (thiếu IV hoặc dữ liệu)")
        if password is not None and key is None:
            raise ValueError("File này được mã hóa bằng khóa 16 byte trực tiếp, vui lòng dùng --key thay vì --password")
        if key is None:
            raise ValueError("Cần cung cấp khóa `key` (16 byte) để giải mã file")
        iv = payload[:16]
        ciphertext = payload[16:]
        aes = AES(key)

    plaintext = aes.decrypt_cbc(ciphertext, iv)
    out.write_bytes(plaintext)
    return hashlib.sha256(plaintext).hexdigest()
