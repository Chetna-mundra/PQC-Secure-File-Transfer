import hashlib
import hmac
import os

#constants
Q = 3329          #modulus, q = 13*2^8 + 1
N = 256           #polynomial degree - ring R_q = Z_q[X] / (X^256 + 1)
ZETA = 17         #primitive 256-th root of unity mod q
INV_128 = 3303    #128^{-1} mod q

PARAMS = {
    "ML-KEM-512":  dict(k=2, eta1=3, eta2=2, du=10, dv=4),
    "ML-KEM-768":  dict(k=3, eta1=2, eta2=2, du=10, dv=4),
    "ML-KEM-1024": dict(k=4, eta1=2, eta2=2, du=11, dv=5),
}


def _bitrev7(x: int) -> int:
    return int(f"{x:07b}"[::-1], 2)

ZETAS = [pow(ZETA, _bitrev7(i), Q) for i in range(128)]            # for NTT
GAMMAS = [pow(ZETA, 2 * _bitrev7(i) + 1, Q) for i in range(128)]   # for base-case mult

#validation
def _require_bytes(value, length, name):
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray")
    if len(value) != length:
        raise ValueError(f"{name} must contain exactly {length} bytes")
    return bytes(value)

def _require_array(values, length, modulus, name="coefficients"):
    if len(values) != length:
        raise ValueError(f"{name} must contain exactly {length} integers")
    if any(not isinstance(x, int) or not 0 <= x < modulus for x in values):
        raise ValueError(f"{name} must be integers in [0, {modulus - 1}]")

def _require_d(d, maximum=12):
    if not isinstance(d, int) or not 1 <= d <= maximum:
        raise ValueError(f"d must be an integer from 1 to {maximum}")

#hashes
def H(x: bytes) -> bytes:
    """SHA3-256(variable length input and fixed length output) return 32 bytes."""
    return hashlib.sha3_256(x).digest()

def G(x: bytes) -> bytes:
    """SHA3-512(variable length input and fixed length output) return 64 bytes; used by splitting into two 32-byte halves."""
    return hashlib.sha3_512(x).digest()


def J(x: bytes) -> bytes:
    """SHAKE256(variable length input and variable length output) with a 32-byte output (used for implicit rejection)."""
    return hashlib.shake_256(x).digest(32)


def PRF(eta: int, s: bytes, b: int) -> bytes:
    """Expand a 32-byte seed and a one-byte nonce into 64*eta bytes."""
    s = _require_bytes(s, 32, "PRF seed")
    if eta not in (2, 3):
        raise ValueError("eta must be 2 or 3")
    if not isinstance(b, int) or not 0 <= b <= 255:
        raise ValueError("nonce must be an integer from 0 to 255")
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


class XOF:
    """SHAKE128, with absorb followed by advancing squeeze. hashlib.digest(n) always returns the FIRST n bytes, not the next n.
    Cache is a growing prefix and maintain an offset to implement FIPS squeeze. Lengths here are measured in BYTES, not bits."""
    def __init__(self):
        self._state = hashlib.shake_128()
        self._offset = 0#Output bytes already generated and stored
        self._cache = b""#Position of the next unread byte
        self._squeezing = False

    def absorb(self, data):
        if self._squeezing:
            raise ValueError("cannot absorb after squeezing")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("XOF input must be bytes or bytearray")
        self._state.update(data)

    def squeeze(self, length):
        if not isinstance(length, int) or length < 0:
            raise ValueError("squeeze length must be a nonnegative integer")
        self._squeezing = True
        end = self._offset + length
        if end > len(self._cache):
            self._cache = self._state.digest(max(end, 168, 2 * len(self._cache)))
        result = self._cache[self._offset:end]
        self._offset = end
        return result

#polynomial arithmetic
def poly_add(a, b):
    _require_array(a, N, Q)
    _require_array(b, N, Q)
    return [(a[i] + b[i]) % Q for i in range(N)]
def poly_sub(a, b):
    _require_array(a, N, Q)
    _require_array(b, N, Q)
    return [(a[i] - b[i]) % Q for i in range(N)]

#forward NTT
def ntt(f):
    _require_array(f, N, Q)
    f = list(f)
    i, ln = 1, 128
    while ln >= 2:
        for start in range(0, N, 2 * ln):
            z = ZETAS[i]
            i += 1
            for j in range(start, start + ln):
                t = z * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f

#Inverse NTT
def ntt_inv(f):
    _require_array(f, N, Q)
    f = list(f)
    i, ln = 127, 2
    while ln <= 128:
        for start in range(0, N, 2 * ln):
            z = ZETAS[i]
            i -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = z * (f[j + ln] - t) % Q
        ln *= 2
    return [x * INV_128 % Q for x in f]

def ntt_mul(f, g):
    """Pointwise product in the NTT domain. The NTT here is 'incomplete': it splits X^256+1 into 128 quadratics
    X^2 - gamma_i, so each coefficient PAIR is multiplied mod (X^2 - gamma_i)."""
    _require_array(f, N, Q)
    _require_array(g, N, Q)
    h = [0] * N
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i], h[2 * i + 1] = base_case_multiply(a0, a1, b0, b1, GAMMAS[i])
    return h

def base_case_multiply(a0, a1, b0, b1, gamma):
    """Algorithm 12: (a0+a1*X)(b0+b1*X), using X^2 = gamma."""
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1

#encoding / compression
def bits_to_bytes(bits):
    """every group of 8 bits becomes one byte, LOW bit first.
    Example from FIPS: [1,1,0,1,0,0,0,1] becomes bytes([139])."""
    if len(bits) % 8 != 0:
        raise ValueError("bit-array length must be a multiple of 8")
    _require_array(bits, len(bits), 2, "bits")
    output = bytearray(len(bits) // 8)
    for i in range(len(bits)):
        output[i // 8] += bits[i] * (2 ** (i % 8))
    return bytes(output)

def bytes_to_bits(data):
    """Expand each byte into 8 bits, LOW bit first."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    bits = []
    for value in data:
        for j in range(8):
            bits.append(value % 2)
            value //= 2
    return bits

def byte_encode(f, d):
    """256 integers -> 32*d bytes"""
    _require_d(d)
    modulus = Q if d == 12 else 2 ** d
    _require_array(f, N, modulus)
    bits = []
    for value in f:
        for j in range(d):
            bits.append(value % 2)
            value //= 2
    return bits_to_bytes(bits)

def byte_decode(b, d):
    """32*d bytes -> 256 integers"""
    _require_d(d)
    b = _require_bytes(b, 32 * d, "encoded polynomial")
    modulus = Q if d == 12 else 2 ** d
    bits = bytes_to_bits(b)
    f = []
    for i in range(N):
        value = 0
        for j in range(d):
            value += bits[i * d + j] * (2 ** j)
        f.append(value % modulus)
    return f

def compress(f, d):
    """applied to each integer.Exact integer rounding."""
    _require_d(d, 11)
    _require_array(f, len(f), Q)
    return [((x * (2 ** d) + Q // 2) // Q) % (2 ** d) for x in f]

def decompress(f, d):
    """applied to each integer. Half-integers round UP."""
    _require_d(d, 11)
    _require_array(f, len(f), 2 ** d)
    return [(y * Q + 2 ** (d - 1)) // (2 ** d) for y in f]

#sampling
def sample_ntt(seed34: bytes):
    """rejection sampling directly into the NTT domain.
    Split each 3-byte block into two 12-bit candidates. Keep only values
    below 3329; reducing rejected values modulo q would introduce bias."""
    seed34 = _require_bytes(seed34, 34, "SampleNTT input")
    ctx = XOF()
    ctx.absorb(seed34)
    output = []
    while len(output) < N:
        c = ctx.squeeze(3)
        d1 = c[0] + 256 * (c[1] % 16)
        d2 = c[1] // 16 + 16 * c[2]
        if d1 < Q:
            output.append(d1)
        if d2 < Q and len(output) < N:
            output.append(d2)
    return output

def sample_cbd(b: bytes, eta: int):
    """count eta bits minus the next eta bits, per coefficient.
    Small negative values are stored modulo q: for example, -1 becomes 3328."""
    if eta not in (2, 3):
        raise ValueError("eta must be 2 or 3")
    b = _require_bytes(b, 64 * eta, "CBD input")
    bits = bytes_to_bits(b)
    f = []
    for i in range(N):
        start = 2 * i * eta
        x = sum(bits[start:start + eta])
        y = sum(bits[start + eta:start + 2 * eta])
        f.append((x - y) % Q)
    return f

#the scheme
class MLKEM:
    def __init__(self, name: str = "ML-KEM-768"):
        if name not in PARAMS:
            raise ValueError("choose ML-KEM-512, ML-KEM-768, or ML-KEM-1024")
        p = PARAMS[name]
        self.name = name
        self.k, self.eta1, self.eta2, self.du, self.dv = p["k"], p["eta1"], p["eta2"], p["du"], p["dv"]
        self.ek_size = 384 * self.k + 32
        self.dk_size = 768 * self.k + 96
        self.ct_size = 32 * (self.du * self.k + self.dv)
        self.ss_size = 32

    #helpers
    def _matrix(self, rho):
        return [[sample_ntt(rho + bytes([j, i])) for j in range(self.k)] for i in range(self.k)]

    def _matvec(self, A, v, transpose=False):
        out = []
        for i in range(self.k):
            acc = [0] * N
            for j in range(self.k):
                a = A[j][i] if transpose else A[i][j]
                acc = poly_add(acc, ntt_mul(a, v[j]))
            out.append(acc)
        return out

    def _dot(self, u, v):
        acc = [0] * N
        for a, b in zip(u, v):
            acc = poly_add(acc, ntt_mul(a, b))
        return acc

    #K-PKE: the underlying Module-LWE public-key encryption
    def _pke_keygen(self, d: bytes):
        """Algorithm 13: generate t_hat = A_hat*s_hat + e_hat."""
        d = _require_bytes(d, 32, "d")#d is a random seed
        g = G(d + bytes([self.k]))#generate 64 bits
        rho, sigma = g[:32], g[32:]#split 64 into 32 32
        A = self._matrix(rho)
        s = [sample_cbd(PRF(self.eta1, sigma, i), self.eta1) for i in range(self.k)]
        e = [sample_cbd(PRF(self.eta1, sigma, self.k + i), self.eta1) for i in range(self.k)]
        s_hat = [ntt(p) for p in s]
        e_hat = [ntt(p) for p in e]
        As = self._matvec(A, s_hat)
        t_hat = [poly_add(As[i], e_hat[i]) for i in range(self.k)]#t = A s + e  (the LWE sample)
        ek = b"".join(byte_encode(p, 12) for p in t_hat) + rho
        dk = b"".join(byte_encode(p, 12) for p in s_hat)
        return ek, dk

    def _pke_encrypt(self, ek: bytes, m: bytes, r: bytes) -> bytes:
        """Algorithm 14: u = A^T*y + e1; v = t^T*y + e2 + message."""
        ek = _require_bytes(ek, self.ek_size, "PKE encryption key")
        m = _require_bytes(m, 32, "message")
        r = _require_bytes(r, 32, "encryption randomness")
        k = self.k
        t_hat = [byte_decode(ek[384 * i: 384 * (i + 1)], 12) for i in range(k)]
        rho = ek[384 * k:]
        A = self._matrix(rho)
        y = [sample_cbd(PRF(self.eta1, r, i), self.eta1) for i in range(k)]
        e1 = [sample_cbd(PRF(self.eta2, r, k + i), self.eta2) for i in range(k)]
        e2 = sample_cbd(PRF(self.eta2, r, 2 * k), self.eta2)
        y_hat = [ntt(p) for p in y]
        Aty = self._matvec(A, y_hat, transpose=True)
        u = [poly_add(ntt_inv(Aty[i]), e1[i]) for i in range(k)]
        mu = decompress(byte_decode(m, 1), 1)#message -> {0, ~q/2}
        v = poly_add(poly_add(ntt_inv(self._dot(t_hat, y_hat)), e2), mu)
        c1 = b"".join(byte_encode(compress(p, self.du), self.du) for p in u)
        c2 = byte_encode(compress(v, self.dv), self.dv)
        return c1 + c2

    def _pke_decrypt(self, dk: bytes, c: bytes) -> bytes:
        """Algorithm 15: subtract s^T*u from v, then recover message bits."""
        dk = _require_bytes(dk, 384 * self.k, "PKE decryption key")
        c = _require_bytes(c, self.ct_size, "ciphertext")
        k, du, dv = self.k, self.du, self.dv
        c1, c2 = c[: 32 * du * k], c[32 * du * k:]
        u = [decompress(byte_decode(c1[32 * du * i: 32 * du * (i + 1)], du), du) for i in range(k)]
        v = decompress(byte_decode(c2, dv), dv)
        s_hat = [byte_decode(dk[384 * i: 384 * (i + 1)], 12) for i in range(k)]
        u_hat = [ntt(p) for p in u]
        w = poly_sub(v, ntt_inv(self._dot(s_hat, u_hat)))# = mu + small noise
        return byte_encode(compress(w, 1), 1)# round back to bits

    #ML-KEM internal
    def keygen_internal(self, d: bytes, z: bytes):
        """Algorithm 16. Deterministic: fixed d,z give fixed ek,dk."""
        d = _require_bytes(d, 32, "d")
        z = _require_bytes(z, 32, "z")
        ek, dk_pke = self._pke_keygen(d)
        return ek, dk_pke + ek + H(ek) + z

    def encaps_internal(self, ek: bytes, m: bytes):
        """Algorithm 17. Deterministic test entry; ek must already be checked."""
        ek = _require_bytes(ek, self.ek_size, "encapsulation key")
        m = _require_bytes(m, 32, "m")
        g = G(m + H(ek))
        K, r = g[:32], g[32:]
        return K, self._pke_encrypt(ek, m, r)

    def decaps_internal(self, dk: bytes, c: bytes) -> bytes:
        """Algorithm 18. Inputs must already pass the public API checks."""
        dk = _require_bytes(dk, self.dk_size, "decapsulation key")
        c = _require_bytes(c, self.ct_size, "ciphertext")
        k = self.k
        dk_pke = dk[: 384 * k]
        ek_pke = dk[384 * k: 768 * k + 32]
        h = dk[768 * k + 32: 768 * k + 64]
        z = dk[768 * k + 64:]
        m2 = self._pke_decrypt(dk_pke, c)
        g = G(m2 + h)
        K2, r2 = g[:32], g[32:]
        K_bar = J(z + c)#implicit-rejection key
        c2 = self._pke_encrypt(ek_pke, m2, r2)# re-encrypt and compare
        return K2 if hmac.compare_digest(c, c2) else K_bar

    #public API - the final MLKEM functions to be called
    def keygen(self):
        """return (public encapsulation key, private decapsulation key)."""
        return self.keygen_internal(os.urandom(32), os.urandom(32))

    def encaps(self, ek: bytes):
        """Return (shared key, ciphertext)."""
        ek = _require_bytes(ek, self.ek_size, "encapsulation key")
        for i in range(self.k):#modulus check
            seg = ek[384 * i: 384 * (i + 1)]
            if byte_encode(byte_decode(seg, 12), 12) != seg:
                raise ValueError("encapsulation key failed modulus check")
        return self.encaps_internal(ek, os.urandom(32))

    def decaps(self, dk: bytes, c: bytes) -> bytes:
        """Return a 32-byte shared key."""
        c = _require_bytes(c, self.ct_size, "ciphertext")
        dk = _require_bytes(dk, self.dk_size, "decapsulation key")
        if H(dk[384 * self.k: 768 * self.k + 32]) != dk[768 * self.k + 32: 768 * self.k + 64]:
            raise ValueError("decapsulation key hash check failed")
        return self.decaps_internal(dk, c)

if __name__ == "__main__":
    for parameter_set in PARAMS:
        kem = MLKEM(parameter_set)
        ek, dk = kem.keygen()
        shared_key, ciphertext = kem.encaps(ek)
        recovered_key = kem.decaps(dk, ciphertext)
        if shared_key != recovered_key:
            raise RuntimeError("shared-key agreement failed")
        print(f"{parameter_set}: shared keys match; "
              f"ek={len(ek)}, dk={len(dk)}, ciphertext={len(ciphertext)} bytes")

#pk, sk = kem.keygen()
#ciphertext, shared_secret_server = kem.encaps(pk)
#shared_secret_client = kem.decaps(sk, ciphertext)
