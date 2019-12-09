import random
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def calc_inverse(n, ele):
    a = n
    b = ele % n
    t_0 = 0
    t = 1
    q = a // b
    r = a % b
    while r > 0:
        temp = (t_0 - q*t) % n
        t_0 = t
        t = temp
        a = b
        b = r
        q = a // b
        r = a % b

    return t


def modular_exponent(a, b, n):
    mask = 1
    result = 1
    while mask <= b:
        if mask & b:
            result = (result * a) % n
        a = (a * a) % n
        mask = mask << 1
    return result


def sha_256(string: str):
    hash_func = hashlib.sha256()
    hash_func.update(string.encode("utf-8"))
    string_hash_bytes = hash_func.digest()
    return int.from_bytes(string_hash_bytes, byteorder="big")
    # return 22


class DSA:
    def __init__(self, p, q, alpha, beta, a):
        self.p = p
        self.q = q
        self.alpha = alpha
        self.beta = beta
        self.a = a

    def sign(self, message: str):
        random_k = random.randrange(1, self.q)
        # random_k = 50

        gamma = modular_exponent(self.alpha, random_k, self.p) % self.q
        delta = ((sha_256(message) + self.a * gamma) *
                 calc_inverse(self.q, random_k)) % self.q

        logger.info("签名函数")
        logger.info("消息：{0}\n签名：\n Gamma: {1} \n Delta: {2}".format(
            message, gamma, delta))
        return (gamma, delta)

    def verify(self, signature: tuple, message):
        gamma, delta = signature
        delta_inverse = calc_inverse(self.q, delta)
        e_1 = (sha_256(message) * delta_inverse) % self.q
        e_2 = (gamma * delta_inverse) % self.q

        gamma_verify = ((modular_exponent(self.alpha, e_1, self.p) *
                         modular_exponent(self.beta, e_2, self.p)) % self.p) % self.q

        logger.info("验证函数")
        logger.info("消息：{0}\n签名：\n Gamma: {1} \n Delta: {2}".format(
            message, gamma, delta))

        if gamma_verify == gamma:
            print("签名认证成功")
        else:
            print("签名认证失败")
