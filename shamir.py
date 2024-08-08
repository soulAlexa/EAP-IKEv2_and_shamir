
import math
import sympy
import random
import numpy as np
def gen_prime():
    t = list(sympy.primerange(1 << 6, 1 << 12))
    return t[random.randint(0, len(t))]
def mod_pow(base, exp, mod):
    out = 1
    while exp > 0:
        if exp & 1:
            out = (out*base) % mod
        exp >>= 1
        base = (base*base) % mod
    return out

def _mod(a, m):
    a %= m
    if a < 0:
        a += m
    return a
def gcd(a, b):
    if not a:
        return b, 0, 1
    d, x, y = gcd(b % a, a)
    return d, y-int(b/a)*x, x


def getrev(a, mod):
    if a < 0:
        a = a % mod + mod
    g, x, _ = gcd(a, mod)
    if g != 1:
        return -1
    else:
        return (x % mod + mod) % mod


def crypt(M, k, n):
    def calc_val(x, pol, p1):
        out = 0
        for k, p in pol:
            out += (k * mod_pow(x, p, p1)) % p1
        return out
    p = 3
    while p < M:
        p = gen_prime()
    pol = [(M, 0)]
    for i in range(1, k):
        pol.append((random.randint(0, p), i))
    print(f'npol = {pol[0]}', end='')
    for k, s in pol[1:]:
        print(f' + {k} * x^{s}', end='')
    print('\n')
    out = []
    for i in range(n):
        r = random.randint(0, p)
        out.append((r, calc_val(r, pol, p)))
    return out, p

def decrypt(points, k, p):
    if len(points) < k:
        return -1
    table = []
    for i in range(0, k):
        table.append(np.zeros(k - i))
        table[i][0] = points[i][1]

    for i in range(1, k):
        for ii in range(k-i):
            table[ii][i] = _mod((table[ii + 1][i - 1] - table[ii][i - 1]) * getrev(points[i + ii][0] - points[ii][0], p), p)
    t, tt = table[0], 1
    out = t[0]
    for i in range(1, len(t)):
        tt = _mod(tt * (-points[i - 1][0]), p)
        out = _mod(out + tt * t[i], p)
    return out


if __name__ == '__main__':
    M, k, n = 333, 40, 55
    points, p = crypt(M, k, n)
    print(f'modP = {p}\n')
    p2 = decrypt(points, k, p)
    print(f'decr = {p2}')
