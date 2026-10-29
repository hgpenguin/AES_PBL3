"""Known-answer tests from FIPS 197 (2001), C.1, and NIST AES_Core128.

Run: python -m unittest -v
Reference links and the distinction between standard versions are in README.md.
"""

import subprocess
import sys
import unittest
from pathlib import Path

from aes import encrypt_block, expand_key, xtime

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

# SubBytes, ShiftRows, MixColumns, AddRoundKey for rounds 1..9.
# Round 10 omits MixColumns. These values are independent reference data.
ROUND_STATES = """
63cab7040953d051cd60e0e7ba70e18c
6353e08c0960e104cd70b751bacad0e7
5f72641557f5bc92f7be3b291db9f91a
89d810e8855ace682d1843d8cb128fe4
a761ca9b97be8b45d8ad1a611fc97369
a7be1a6997ad739bd8c9ca451f618b61
ff87968431d86a51645151fa773ad009
4915598f55e5d7a0daca94fa1f0a63f7
3b59cb73fcd90ee05774222dc067fb68
3bd92268fc74fb735767cbe0c0590e2d
4c9c1e66f771f0762c3f868e534df256
fa636a2825b339c940668a3157244d17
2dfb02343f6d12dd09337ec75b36e3f0
2d6d7ef03f33e334093602dd5bfb12c7
6385b79ffc538df997be478e7547d691
247240236966b3fa6ed2753288425b6c
36400926f9336d2d9fb59d23c42c3950
36339d50f9b539269f2c092dc4406d23
f4bcd45432e554d075f1d6c51dd03b3c
c81677bc9b7ac93b25027992b0261996
e847f56514dadde23f77b64fe7f7d490
e8dab6901477d4653ff7f5e2e747dd4f
9816ee7400f87f556b2c049c8e5ad036
c62fe109f75eedc3cc79395d84f9cf5d
b415f8016858552e4bb6124c5f998a4c
b458124c68b68a014b99f82e5f15554c
c57e1c159a9bd286f05f4be098c63439
d1876c0f79c4300ab45594add66ff41f
3e175076b61c04678dfc2295f6a8bfc0
3e1c22c0b6fcbf768da85067f6170495
baa03de7a1f9b56ed5512cba5f414d23
fde3bad205e5d0d73547964ef1fe37f1
5411f4b56bd9700e96a0902fa1bb9aa1
54d990a16ba09ab596bbf40ea111702f
e9f74eec023020f61bf2ccf2353c21c7
bd6e7c3df2b5779e0b61216e8b10b689
7a9f102789d5f50b2beffd9f3dca4ea7
7ad5fda789ef4e272bca100b3d9ff59f
69c4e0d86a7b0430d8cdb78070b4c55a
""".split()

ROUND_KEYS = """
000102030405060708090a0b0c0d0e0f
d6aa74fdd2af72fadaa678f1d6ab76fe
b692cf0b643dbdf1be9bc5006830b3fe
b6ff744ed2c2c9bf6c590cbf0469bf41
47f7f7bc95353e03f96c32bcfd058dfd
3caaa3e8a99f9deb50f3af57adf622aa
5e390f7df7a69296a7553dc10aa31f6b
14f9701ae35fe28c440adf4d4ea9c026
47438735a41c65b9e016baf4aebf7ad2
549932d1f08557681093ed9cbe2c974e
13111d7fe3944a17f307a78b4d2b30c5
""".split()


class AESTests(unittest.TestCase):
    def test_fips_ciphertext(self):
        self.assertEqual(encrypt_block(PLAINTEXT, KEY), CIPHERTEXT)

    def test_nist_core_blocks(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        vectors = (
            ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
            ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
            ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
            ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
        )
        for plaintext, expected in vectors:
            with self.subTest(plaintext=plaintext):
                self.assertEqual(encrypt_block(bytes.fromhex(plaintext), key).hex(), expected)

    def test_all_round_keys(self):
        self.assertEqual([key.hex() for key in expand_key(KEY)], ROUND_KEYS)

    def test_every_intermediate_state(self):
        events = []
        result = encrypt_block(PLAINTEXT, KEY, trace=lambda r, s, v: events.append((r, s, v.hex())))
        self.assertEqual(result, CIPHERTEXT)
        expected = [(0, "Input", PLAINTEXT.hex()), (0, "RoundKey", ROUND_KEYS[0]),
                    (0, "AddRoundKey", "00102030405060708090a0b0c0d0e0f0")]
        states = iter(ROUND_STATES)
        for round_number in range(1, 11):
            for step in ("SubBytes", "ShiftRows"):
                expected.append((round_number, step, next(states)))
            if round_number < 10:
                expected.append((round_number, "MixColumns", next(states)))
            expected.append((round_number, "RoundKey", ROUND_KEYS[round_number]))
            expected.append((round_number, "AddRoundKey", next(states)))
        self.assertEqual(events, expected)

    def test_xtime_reduction(self):
        # FIPS 197-upd1, section 4.2, equation 4.6.
        self.assertEqual(xtime(0x57), 0xAE)
        self.assertEqual(xtime(0xAE), 0x47)
        self.assertEqual(xtime(0x47), 0x8E)
        self.assertEqual(xtime(0x8E), 0x07)

    def test_reject_invalid_blocks_and_keys(self):
        for size in (0, 1, 15, 17, 24, 32):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    encrypt_block(bytes(size), KEY)
                with self.assertRaises(ValueError):
                    encrypt_block(PLAINTEXT, bytes(size))
        for value in ("0" * 16, None, 16):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    encrypt_block(value, KEY)
                with self.assertRaises(TypeError):
                    expand_key(value)

    def test_cli_inputs(self):
        demo = str(Path(__file__).with_name("demo.py"))
        cases = (
            ([], 0),
            (["--text", "AES week 2 demo!"], 0),
            (["--plaintext", "zz"], 2),
            (["--key", "00"], 2),
            (["--text", "é" * 16], 2),  # 16 characters, but 32 UTF-8 bytes.
            (["--text", "", "--plaintext", PLAINTEXT.hex()], 2),
        )
        for arguments, expected_code in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, demo, *arguments], capture_output=True)
                self.assertEqual(result.returncode, expected_code, result.stderr)


if __name__ == "__main__":
    unittest.main()
