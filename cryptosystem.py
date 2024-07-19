from secrets import randbelow,token_bytes
import numpy as np
import random
from math import ceil
from bitarray import bitarray

MARSENE_N_ALL = [82589933,77232917,74207281,57885161,43112609,42643801,37156667,\
             32582657,30402457,25964951,24036583,20996011,13466917,6972593,3021377,2976221,\
             1398269,1257787,859433,756839,216091,132049,86243,44497,23209,21701]

MARSENE_N = [44497,23209,21701]


def create_bitarray(n, ham_dist=None):

    if ham_dist == None:
        #not bit by bit...
        byte_length = (n + 7) // 8
        random_bytes = token_bytes(byte_length)
        random_bitarray = bitarray()
        random_bitarray.frombytes(random_bytes)
        random_bitarray = random_bitarray[:n]  # Truncate to exactly n bits

        return random_bitarray
    else:

        arr = bitarray(n)
        arr.setall(0)

        while ham_dist > 0:
            index = randbelow(n)
            while arr[index] == 1:
                index = randbelow(n)
            arr[index] = 1
            ham_dist -= 1


        return arr

def oracleH(seed, n, h):

    x = len(seed)//4
    s1= seed[:x]
    s2= seed[x:2*x]
    s3= seed[2*x:3*x]
    s4= seed[3*x:]
    H0 = bitarray()
    H1 = bitarray(n)
    H2 = bitarray(n)
    H3 = bitarray(n)
    H1.setall(0)
    H2.setall(0)
    H3.setall(0)

    # randbelow from secrets cannot be seeded
    random_generator = random.Random()
    random_generator.seed(s1.to01())
    for i in range(len(seed)):
        H0.append(random_generator.randint(0, 1))

    #use different seeds for each output, to make them independent
    for H,s in ((H1,s2),(H2,s3),(H3,s4)):
        weight = h
        random_generator = random.Random()
        random_generator.seed(s.to01())
        while weight > 0:
            index = random_generator.randint(0, n - 1)

            while H[index] == 1:
                index = random_generator.randint(0, n - 1)

            H[index] = 1

            weight -= 1

    return H0, H1, H2, H3



class Cryptosystem:

    def __init__(self, sec_param = 256):
        self.sec_param = sec_param

        #security bound
        min = 10*self.sec_param*self.sec_param

        marsenne_n = [n for n in MARSENE_N_ALL if n > min ]

        index = randbelow(len(marsenne_n))
        self.n = marsenne_n[index]

        self.R = create_bitarray(self.n)
        self.F = create_bitarray(self.n, ham_dist=self.sec_param)
        self.G = create_bitarray(self.n, ham_dist=self.sec_param)
        self.h = self.sec_param


    def encode(self, m):
        N = self.n//self.sec_param
        expanded_bit_array = bitarray()
        for bit in m:
                expanded_bit_array.extend([bit] * N)
        b = bitarray(1)
        b[0] = 0
        expanded_bit_array.extend([b[0]]*(self.n-N*self.sec_param))
        return expanded_bit_array


    def gen_keys(self):
        self.SK = self.F
        self.PK = (self.R, (self.R&self.F)|self.G)
        return self.PK, self.SK

    def encrypt(self, text):
        txt = self.encode(text)
        R,T = self.PK
        A = create_bitarray(self.n, ham_dist=self.sec_param)
        B1 = create_bitarray(self.n, ham_dist=self.sec_param)
        B2 = create_bitarray(self.n, ham_dist=self.sec_param)
        C1 = (A&R)|B1
        C2 = ((A&T)|B2)^txt
        return C1, C2

    def decode(self,m):
        decoded =  bitarray(self.sec_param)
        N = self.n//self.sec_param
        for i in range(self.sec_param):

            bits = m[:N]
            count = bits.count(1)
            count0 = bits.count(0)

            if count >= N//2:
                decoded[i] = 1
            else:
                decoded[i] = 0
            m = m[N:]

        return decoded


    def decrypt(self, encrypted):
        C1,C2 = encrypted
        cyphertext = (self.SK&C1)^C2
        return self.decode(cyphertext)


    # input: PK (do parceiro)
    def encapsulate(self):
        K = create_bitarray(self.sec_param) # random bit array
        S, A, B1, B2 = oracleH(K, self.n, self.h)
        R,T = self.PK
        encode = self.encode(K)
        C1 = (A&R)|B1
        C2 = encode^(A&T|B2)
        return (C1, C2), S


    def decapsulate(self, cyphertext):
        C1, C2 = cyphertext
        R,T = self.PK # PK (do proprio)
        K_prime = self.decode((self.SK&C1)^C2)
        S_prime, A_prime, B1_prime, B2_prime = oracleH(K_prime, self.n, self.h)
        encode = self.encode(K_prime)
        C1_prime = (A_prime&R)|B1_prime
        C2_prime = encode^(A_prime&T|B2_prime)
        C_prime = (C1_prime, C2_prime)
        if cyphertext == C_prime:
            return S_prime
        else:
            return None



cryptosystem = Cryptosystem(sec_param=256)

print("n: ", cryptosystem.n)
cryptosystem.gen_keys()

text = 'O rato roeu a rolha do rei da Russia.'
mensagem = bitarray()
mensagem.frombytes(text.encode('utf-8'))

print("-------- Encrypt/Decrypt test -------")
encrypted = cryptosystem.encrypt(mensagem)
decrypted = cryptosystem.decrypt(encrypted)
decrypted_text = decrypted.tobytes().decode('utf-8')
print("text: ", text)
print("text in bits:", mensagem.to01())
print("decrypted text in bits:", decrypted.to01())
print("decrypted text: ", decrypted_text)
print("text in bits == decrypted text in bits: ", mensagem == decrypted)
print("text == decrypted text: ", text == decrypted_text)
print()

print("-------- Oracle test -------")
test_seed = create_bitarray(cryptosystem.sec_param)
oracle = oracleH(test_seed, cryptosystem.n, cryptosystem.h)
print(oracle[0].to01())
oracle1 = oracleH(test_seed, cryptosystem.n, cryptosystem.h)
print(oracle1[0].to01())
print("oracle == oracle1: ", oracle == oracle1)
print()

print("-------- Encaps/Decaps test -------")
cyphertext, encaps_key = cryptosystem.encapsulate()
print("Encaps key: ", encaps_key.to01())
decaps_key = cryptosystem.decapsulate(cyphertext)
print("Decaps key: ", decaps_key.to01())
print("Encaps key == Decaps key: ", encaps_key == decaps_key)
