import os
import random
import unittest

import mlkem
from mlkem import MLKEM, Q, N, ntt, ntt_inv, ntt_mul, byte_encode, byte_decode, compress, decompress


def schoolbook_mul(a, b):
    """Reference multiplication in Z_q[X]/(X^256+1)."""
    r = [0] * N
    for i in range(N):
        for j in range(N):
            k = i + j
            if k < N:
                r[k] = (r[k] + a[i] * b[j]) % Q
            else:
                r[k - N] = (r[k - N] - a[i] * b[j]) % Q
    return r


class TestMath(unittest.TestCase):
    def test_ntt_roundtrip(self):
        f = [random.randrange(Q) for _ in range(N)]
        self.assertEqual(ntt_inv(ntt(f)), f)

    def test_ntt_mul_matches_schoolbook(self):
        a = [random.randrange(Q) for _ in range(N)]
        b = [random.randrange(Q) for _ in range(N)]
        self.assertEqual(ntt_inv(ntt_mul(ntt(a), ntt(b))), schoolbook_mul(a, b))

    def test_encode_decode(self):
        for d in (1, 4, 10, 11, 12):
            f = [random.randrange(Q if d == 12 else 1 << d) for _ in range(N)]
            self.assertEqual(byte_decode(byte_encode(f, d), d), f)

    def test_compress_error_bound(self):
        for d in (4, 10):
            for x in range(Q):
                err = min((decompress(compress([x], d), d)[0] - x) % Q, (x - decompress(compress([x], d), d)[0]) % Q)
                self.assertLessEqual(err, round(Q / 2 ** (d + 1)))


class TestKEM(unittest.TestCase):
    def test_roundtrip_all_levels(self):
        for name in mlkem.PARAMS:
            kem = MLKEM(name)
            for _ in range(5):
                ek, dk = kem.keygen()
                K, c = kem.encaps(ek)
                self.assertEqual(kem.decaps(dk, c), K)
                self.assertEqual((len(ek), len(dk), len(c)), (kem.ek_size, kem.dk_size, kem.ct_size))

    def test_implicit_rejection(self):
        kem = MLKEM()
        ek, dk = kem.keygen()
        K, c = kem.encaps(ek)
        bad = bytearray(c)
        bad[7] ^= 1
        K_bad = kem.decaps(dk, bytes(bad))
        self.assertNotEqual(K_bad, K)                       # different key, but no exception
        self.assertEqual(K_bad, kem.decaps(dk, bytes(bad)))  # deterministic

    def test_input_validation(self):
        kem = MLKEM()
        ek, dk = kem.keygen()
        with self.assertRaises(ValueError):
            kem.encaps(ek[:-1])
        bad_ek = bytearray(ek)
        bad_ek[0:2] = b"\xff\xff"                           # coefficient >= q
        with self.assertRaises(ValueError):
            kem.encaps(bytes(bad_ek))

    def test_matches_reference(self):
        try:
            from kyber_py.ml_kem import ML_KEM_768 as ref
        except ImportError:
            self.skipTest("kyber-py not installed")
        kem = MLKEM("ML-KEM-768")
        d, z, m = os.urandom(32), os.urandom(32), os.urandom(32)
        ek, dk = kem.keygen_internal(d, z)
        self.assertEqual((ek, dk), ref.key_derive(d + z))
        self.assertEqual(kem.encaps_internal(ek, m), ref._encaps_internal(ek, m))

#Run:  python test_mlkem.py(the cross-check test needs `pip install kyber-py`)
if __name__ == "__main__":
    unittest.main(verbosity=2)
