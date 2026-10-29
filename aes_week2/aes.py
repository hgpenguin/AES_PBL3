"""AES-128 encryption following FIPS 197, with optional round tracing.

State uses column order: state[4 * column + row].
This is an educational block cipher implementation, not a message protocol.
"""

from collections.abc import Callable

BLOCK_SIZE = 16
ROUNDS = 10
Trace = Callable[[int, str, bytes], None]

# FIPS 197, Table 4. Each line corresponds to one high hexadecimal digit.
SBOX = bytes.fromhex(
    "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76"
    "ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0"
    "b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15"
    "04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75"
    "09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84"
    "53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf"
    "d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8"
    "51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2"
    "cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73"
    "60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db"
    "e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79"
    "e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08"
    "ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a"
    "70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e"
    "e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df"
    "8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16"
)


def xtime(value: int) -> int:
    """Multiply a byte by {02} in GF(2^8), modulo x^8+x^4+x^3+x+1."""
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def sub_bytes(state: bytes) -> bytes:
    return bytes(SBOX[value] for value in state)


def shift_rows(state: bytes) -> bytes:
    """Rotate row r to the left by r positions; retain column order."""
    return bytes(
        state[4 * ((column + row) % 4) + row]
        for column in range(4)
        for row in range(4)
    )


def mix_columns(state: bytes) -> bytes:
    """Multiply each column by the FIPS 197 MixColumns matrix."""
    result = bytearray(BLOCK_SIZE)
    for offset in range(0, BLOCK_SIZE, 4):
        a, b, c, d = state[offset:offset + 4]
        # {03} * x = xtime(x) XOR x.
        result[offset:offset + 4] = bytes((
            xtime(a) ^ xtime(b) ^ b ^ c ^ d,
            a ^ xtime(b) ^ xtime(c) ^ c ^ d,
            a ^ b ^ xtime(c) ^ xtime(d) ^ d,
            xtime(a) ^ a ^ b ^ c ^ xtime(d),
        ))
    return bytes(result)


def add_round_key(state: bytes, round_key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(state, round_key, strict=True))


def _require_block(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != BLOCK_SIZE:
        raise ValueError(f"{name} must contain exactly {BLOCK_SIZE} bytes")


def expand_key(key: bytes) -> tuple[bytes, ...]:
    """Expand a 16-byte key into K0 through K10 (44 four-byte words)."""
    _require_block(key, "key")
    words = [key[offset:offset + 4] for offset in range(0, BLOCK_SIZE, 4)]
    rcon = 0x01
    for index in range(4, 4 * (ROUNDS + 1)):
        temp = words[index - 1]
        if index % 4 == 0:
            temp = sub_bytes(temp[1:] + temp[:1])  # RotWord, then SubWord
            temp = bytes((temp[0] ^ rcon,)) + temp[1:]
            rcon = xtime(rcon)
        words.append(add_round_key(words[index - 4], temp))
    return tuple(b"".join(words[i:i + 4]) for i in range(0, len(words), 4))


def encrypt_block(plaintext: bytes, key: bytes, *, trace: Trace | None = None) -> bytes:
    """Encrypt one 16-byte block; trace receives immutable byte snapshots.

    Events: Input, RoundKey, SubBytes, ShiftRows, MixColumns, AddRoundKey.
    No padding, text encoding, mode of operation, or authentication is added.
    """
    _require_block(plaintext, "plaintext")
    round_keys = expand_key(key)

    def record(round_number: int, step: str, value: bytes) -> bytes:
        if trace is not None:
            trace(round_number, step, value)
        return value

    state = record(0, "Input", plaintext)
    record(0, "RoundKey", round_keys[0])
    state = record(0, "AddRoundKey", add_round_key(state, round_keys[0]))

    for round_number in range(1, ROUNDS + 1):
        state = record(round_number, "SubBytes", sub_bytes(state))
        state = record(round_number, "ShiftRows", shift_rows(state))
        if round_number != ROUNDS:
            state = record(round_number, "MixColumns", mix_columns(state))
        record(round_number, "RoundKey", round_keys[round_number])
        state = record(round_number, "AddRoundKey",
                       add_round_key(state, round_keys[round_number]))
    return state
