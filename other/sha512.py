# copied from other open source code
import sys
from prettytable import PrettyTable

MAX_64BIT = 0xFFFFFFFFFFFFFFFF


class SHA512:
    def __init__(self, mode="MODE_SHA_512", verbose=0):
        assert mode in [
            "MODE_SHA_512_224",
            "MODE_SHA_512_256",
            "MODE_SHA_384",
            "MODE_SHA_512",
        ]
        self.mode = mode
        self.verbose = verbose
        self.NUM_ROUNDS = 1  # Only perform one round
        self.H = [0] * 8
        self.t1 = 0
        self.t2 = 0
        self.a = 0
        self.b = 0
        self.c = 0
        self.d = 0
        self.e = 0
        self.f = 0
        self.g = 0
        self.h = 0
        self.w = 0
        self.W = [0] * 16
        self.k = 0
        self.K = [
            0x428A2F98D728AE22,
            0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F,
            0xE9B5DBA58189DBBC,
            0x3956C25BF348B538,
            0x59F111F1B605D019,
            0x923F82A4AF194F9B,
            0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242,
            0x12835B0145706FBE,
            0x243185BE4EE4B28C,
            0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F,
            0x80DEB1FE3B1696B1,
            0x9BDC06A725C71235,
            0xC19BF174CF692694,
            0xE49B69C19EF14AD2,
            0xEFBE4786384F25E3,
            0x0FC19DC68B8CD5B5,
            0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275,
            0x4A7484AA6EA6E483,
            0x5CB0A9DCBD41FBD4,
            0x76F988DA831153B5,
            0x983E5152EE66DFAB,
            0xA831C66D2DB43210,
            0xB00327C898FB213F,
            0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2,
            0xD5A79147930AA725,
            0x06CA6351E003826F,
            0x142929670A0E6E70,
            0x27B70A8546D22FFC,
            0x2E1B21385C26C926,
            0x4D2C6DFC5AC42AED,
            0x53380D139D95B3DF,
            0x650A73548BAF63DE,
            0x766A0ABB3C77B2A8,
            0x81C2C92E47EDAEE6,
            0x92722C851482353B,
            0xA2BFE8A14CF10364,
            0xA81A664BBC423001,
            0xC24B8B70D0F89791,
            0xC76C51A30654BE30,
            0xD192E819D6EF5218,
            0xD69906245565A910,
            0xF40E35855771202A,
            0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8,
            0x1E376C085141AB53,
            0x2748774CDF8EEB99,
            0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63,
            0x4ED8AA4AE3418ACB,
            0x5B9CCA4F7763E373,
            0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC,
            0x78A5636F43172F60,
            0x84C87814A1F0AB72,
            0x8CC702081A6439EC,
            0x90BEFFFA23631E28,
            0xA4506CEBDE82BDE9,
            0xBEF9A3F7B2C67915,
            0xC67178F2E372532B,
            0xCA273ECEEA26619C,
            0xD186B8C721C0C207,
            0xEADA7DD6CDE0EB1E,
            0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA,
            0x0A637DC5A2C898A6,
            0x113F9804BEF90DAE,
            0x1B710B35131C471B,
            0x28DB77F523047D84,
            0x32CAAB7B40C72493,
            0x3C9EBE0A15C9BEBC,
            0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6,
            0x597F299CFC657E2A,
            0x5FCB6FAB3AD6FAEC,
            0x6C44198C4A475817,
        ]

    def init(self):
        if self.mode == "MODE_SHA_512_224":
            self.H = [
                0x8C3D37C819544DA2,
                0x73E1996689DCD4D6,
                0x1DFAB7AE32FF9C82,
                0x679DD514582F9FCF,
                0x0F6D2B697BD44DA8,
                0x77E36F7304C48942,
                0x3F9D85A86A1D36C8,
                0x1112E6AD91D692A1,
            ]

        elif self.mode == "MODE_SHA_512_256":
            self.H = [
                0x22312194FC2BF72C,
                0x9F555FA3C84C64C2,
                0x2393B86B6F53B151,
                0x963877195940EABD,
                0x96283EE2A88EFFE3,
                0xBE5E1E2553863992,
                0x2B0199FC2C85B8AA,
                0x0EB72DDC81C52CA2,
            ]

        elif self.mode == "MODE_SHA_384":
            self.H = [
                0xCBBB9D5DC1059ED8,
                0x629A292A367CD507,
                0x9159015A3070DD17,
                0x152FECD8F70E5939,
                0x67332667FFC00B31,
                0x8EB44A8768581511,
                0xDB0C2E0D64F98FA7,
                0x47B5481DBEFA4FA4,
            ]

        elif self.mode == "MODE_SHA_512":
            print("Setting H to default values")
            self.H = [
                0x6A09E667F3BCC908,
                0xBB67AE8584CAA73B,
                0x3C6EF372FE94F82B,
                0xA54FF53A5F1D36F1,
                0x510E527FADE682D1,
                0x9B05688C2B3E6C1F,
                0x1F83D9ABFB41BD6B,
                0x5BE0CD19137E2179,
            ]
            table = PrettyTable()
            table.field_names = ["Index", "H Value", "H Value (Hex)"]
            for i in range(8):
                table.add_row([f"H[{i}]", self.H[i], hex(self.H[i])])
            print("Input Vector H:")
            print(table)

            table = PrettyTable()
            table.field_names = ["K Index", "K Value", "K Value (Hex)"]
            table.add_row(["K[0]", self.K[0], hex(self.K[0])])
            print("Value of K[0]:")
            print(table)

    def next(self, block):
        self._W_schedule(block)
        self._copy_digest()
        if self.verbose:
            print("State after init:")
            self._print_state(0)

        for i in range(self.NUM_ROUNDS):
            self._sha512_round(i)
            if self.verbose:
                self._print_state(i)

        self._update_digest()

    def get_digest(self):
        if self.mode == "MODE_SHA_512_224":
            return self.H[0:3]  # FIX THIS!

        elif self.mode == "MODE_SHA_512_256":
            return self.H[0:4]

        elif self.mode == "MODE_SHA_384":
            return self.H[0:6]

        elif self.mode == "MODE_SHA_512":
            return self.H

    def _copy_digest(self):
        self.a = self.H[0]
        self.b = self.H[1]
        self.c = self.H[2]
        self.d = self.H[3]
        self.e = self.H[4]
        self.f = self.H[5]
        self.g = self.H[6]
        self.h = self.H[7]

    def _update_digest(self):
        self.H[0] = (self.H[0] + self.a) & MAX_64BIT
        self.H[1] = (self.H[1] + self.b) & MAX_64BIT
        self.H[2] = (self.H[2] + self.c) & MAX_64BIT
        self.H[3] = (self.H[3] + self.d) & MAX_64BIT
        self.H[4] = (self.H[4] + self.e) & MAX_64BIT
        self.H[5] = (self.H[5] + self.f) & MAX_64BIT
        self.H[6] = (self.H[6] + self.g) & MAX_64BIT
        self.H[7] = (self.H[7] + self.h) & MAX_64BIT

    def _print_state(self, round):
        table = PrettyTable()
        table.field_names = ["State", "Hex Value", "Binary Value"]

        table.add_row(["t1", f"0x{self.t1:016x}", format(self.t1, "064b")])
        table.add_row(["t2", f"0x{self.t2:016x}", format(self.t2, "064b")])
        table.add_row(["k", f"0x{self.k:016x}", format(self.k, "064b")])
        table.add_row(["w", f"0x{self.w:016x}", format(self.w, "064b")])
        table.add_row(["a", f"0x{self.a:016x}", format(self.a, "064b")])
        table.add_row(["b", f"0x{self.b:016x}", format(self.b, "064b")])
        table.add_row(["c", f"0x{self.c:016x}", format(self.c, "064b")])
        table.add_row(["d", f"0x{self.d:016x}", format(self.d, "064b")])
        table.add_row(["e", f"0x{self.e:016x}", format(self.e, "064b")])
        table.add_row(["f", f"0x{self.f:016x}", format(self.f, "064b")])
        table.add_row(["g", f"0x{self.g:016x}", format(self.g, "064b")])
        table.add_row(["h", f"0x{self.h:016x}", format(self.h, "064b")])

        print(f"State at round 0x{round:02x}:")
        print(table)

        table = PrettyTable()
        table.field_names = ["H Index", "Hex Value", "Binary Value"]

        for i in range(8):
            table.add_row([f"H[{i}]", f"0x{self.H[i]:016x}", format(self.H[i], "064b")])

        print("H:")
        print(table)
        # print("State at round 0x%02x:" % round)
        # print("t1 = 0x%016x, t2 = 0x%016x" % (self.t1, self.t2))
        # print("k  = 0x%016x, w  = 0x%016x" % (self.k, self.w))
        # print("a  = 0x%016x, b  = 0x%016x" % (self.a, self.b))
        # print("c  = 0x%016x, d  = 0x%016x" % (self.c, self.d))
        # print("e  = 0x%016x, f  = 0x%016x" % (self.e, self.f))
        # print("g  = 0x%016x, h  = 0x%016x" % (self.g, self.h))
        # print("")
        # print("In binary:")
        # print("t1 = %s, t2 = %s" % (format(self.t1, "064b"), format(self.t2, "064b")))
        # print("k  = %s, w  = %s" % (format(self.k, "064b"), format(self.w, "064b")))
        # print("a  = %s, b  = %s" % (format(self.a, "064b"), format(self.b, "064b")))
        # print("c  = %s, d  = %s" % (format(self.c, "064b"), format(self.d, "064b")))
        # print("e  = %s, f  = %s" % (format(self.e, "064b"), format(self.f, "064b")))
        # print("g  = %s, h  = %s" % (format(self.g, "064b"), format(self.h, "064b")))
        # print("")
        # print("H:")
        # for i in range(8):
        #     print("H[%d] = 0x%016x" % (i, self.H[i]))
        # print("")
        # print("In binary:")
        # for i in range(8):
        #     print("H[%d] = %s" % (i, format(self.H[i], "064b")))
        # print("")

    def _sha512_round(self, round):
        self.k = self.K[round]
        self.w = self._next_w(round)
        self.t1 = self._T1(self.e, self.f, self.g, self.h, self.k, self.w)
        self.t2 = self._T2(self.a, self.b, self.c)
        self.h = self.g
        self.g = self.f
        self.f = self.e
        self.e = (self.d + self.t1) & MAX_64BIT
        self.d = self.c
        self.c = self.b
        self.b = self.a
        self.a = (self.t1 + self.t2) & MAX_64BIT

    def _next_w(self, round):
        if round < 16:
            return self.W[round]

        else:
            tmp_w = (
                self._delta1(self.W[14])
                + self.W[9]
                + self._delta0(self.W[1])
                + self.W[0]
            ) & MAX_64BIT
            for i in range(15):
                self.W[i] = self.W[(i + 1)]
            self.W[15] = tmp_w
            return tmp_w

    def _W_schedule(self, block):
        table = PrettyTable()
        table.field_names = ["W Index", "W Value", "W Value (Binary)"]
        for i in range(16):
            self.W[i] = block[i]
            table.add_row([f"W[{i}]", block[i], format(block[i], "064b")])
        print("W Schedule:")
        print(table)

        # for i in range(16):
        #     print("Setting W[%d] = %d" % (i, block[i]), end="")
        #     print("\tBinary: ", format(block[i], "064b"))
        #     self.W[i] = block[i]

    def _Ch(self, e, f, g):
        table = PrettyTable()
        table.field_names = ["Field", "Value", "Hex Value"]
        table.add_row(["e", e, hex(e)])
        table.add_row(["f", f, hex(f)])
        table.add_row(["g", g, hex(g)])
        x_and_y = e & f
        not_x_and_z = ~e & g
        ch_value = x_and_y ^ not_x_and_z
        table.add_row(["e & f", x_and_y, hex(x_and_y)])
        table.add_row(["~e & g", not_x_and_z, hex(not_x_and_z)])
        table.add_row(["Ch(e, f, g) = (e & f) ^ (~e & g)", ch_value, hex(ch_value)])
        print(table)
        return ch_value

    def _Maj(self, a, b, c):
        table = PrettyTable()
        table.field_names = ["Field", "Value", "Hex Value"]

        a_and_b = a & b
        a_and_c = a & c
        b_and_c = b & c
        maj_value = a_and_b ^ a_and_c ^ b_and_c

        table.add_row(["a", a, hex(a)])
        table.add_row(["b", b, hex(b)])
        table.add_row(["c", c, hex(c)])
        table.add_row(["a & b", a_and_b, hex(a_and_b)])
        table.add_row(["a & c", a_and_c, hex(a_and_c)])
        table.add_row(["b & c", b_and_c, hex(b_and_c)])
        table.add_row(["Maj(a, b, c)", maj_value, hex(maj_value)])

        print(table)
        return maj_value

    def _sigma0(self, x):
        table = PrettyTable()
        table.field_names = ["x", "sigma0(x)", "sigma0(x) (Hex)"]
        sigma0_value = self._rotr64(x, 28) ^ self._rotr64(x, 34) ^ self._rotr64(x, 39)
        table.add_row([x, sigma0_value, hex(sigma0_value)])
        print(table)
        return sigma0_value

    def _sigma1(self, x):
        table = PrettyTable()
        table.field_names = ["x", "sigma1(x)", "sigma1(x) (Hex)"]
        sigma1_value = self._rotr64(x, 14) ^ self._rotr64(x, 18) ^ self._rotr64(x, 41)
        table.add_row([x, sigma1_value, hex(sigma1_value)])
        print(table)
        return sigma1_value

    def _delta0(self, x):
        table = PrettyTable()
        table.field_names = ["x", "delta0(x)"]
        delta0_value = self._rotr64(x, 1) ^ self._rotr64(x, 8) ^ self._shr64(x, 7)
        table.add_row([x, delta0_value])
        print(table)
        return self._rotr64(x, 1) ^ self._rotr64(x, 8) ^ self._shr64(x, 7)

    def _delta1(self, x):
        table = PrettyTable()
        table.field_names = ["x", "delta1(x)"]
        delta1_value = self._rotr64(x, 19) ^ self._rotr64(x, 61) ^ self._shr64(x, 6)
        table.add_row([x, delta1_value])
        print(table)
        return self._rotr64(x, 19) ^ self._rotr64(x, 61) ^ self._shr64(x, 6)

    def _T1(self, e, f, g, h, k, w):
        # print(
        #     "T1(%d, %d, %d, %d, %d, %d) = %d"
        #     % (
        #         e,
        #         f,
        #         g,
        #         h,
        #         k,
        #         w,
        #         (h + self._sigma1(e) + self._Ch(e, f, g) + k + w) & MAX_64BIT,
        #     )
        # )
        print(
            f"Calculating T1 by {h} + {self._sigma1(e)} + {self._Ch(e, f, g)} + {k} + {w}"
        )
        print(
            f"Calculating T1 by {hex(h)} + {hex(self._sigma1(e))} + {hex(self._Ch(e, f, g))} + {hex(k)} + {hex(w)}"
        )
        T1_value = (h + self._sigma1(e) + self._Ch(e, f, g) + k + w) & MAX_64BIT
        print(f"Result T1: {T1_value}, in hex: {hex(T1_value)}")
        table = PrettyTable()
        table.field_names = ["Field", "Value", "Hex Value"]
        table.add_row(["e", e, hex(e)])
        table.add_row(["f", f, hex(f)])
        table.add_row(["g", g, hex(g)])
        table.add_row(["h", h, hex(h)])
        table.add_row(["k", k, hex(k)])
        table.add_row(["w", w, hex(w)])
        table.add_row(["T1", T1_value, hex(T1_value)])
        print(table)
        return T1_value

    def _T2(self, a, b, c):
        table = PrettyTable()
        table.field_names = ["Field", "Value", "Hex Value"]
        T2_value = (self._sigma0(a) + self._Maj(a, b, c)) & MAX_64BIT
        table.add_row(["a", a, hex(a)])
        table.add_row(["b", b, hex(b)])
        table.add_row(["c", c, hex(c)])
        table.add_row(["T2", T2_value, hex(T2_value)])
        print(table)
        return T2_value

    def _rotr64(self, n, r):
        print("\tTable 1")
        table1 = PrettyTable()
        table1.field_names = ["Field", "Value", "Binary", "Hex"]
        table1.add_row(["n", n, format(n, "064b"), hex(n)])
        table1.add_row(["r", r, format(r, "064b"), hex(r)])
        print(table1)

        rotr64_value = ((n >> r) | (n << (64 - r))) & MAX_64BIT

        table2 = PrettyTable()
        table2.field_names = [
            "rotr64 (Decimal) n >> r",
            "rotr64 (Binary)",
            "rotr64 (Hex)",
        ]
        table2.add_row([rotr64_value, format(rotr64_value, "064b"), hex(rotr64_value)])
        print("\tTable 2")
        print(table2)
        print(f"{'-'*50}")

        return ((n >> r) | (n << (64 - r))) & MAX_64BIT

    def _shr64(self, n, r):
        table = PrettyTable()
        table.field_names = [
            "n",
            "r",
            "n (Binary)",
            "r (Binary)",
            "shr64 (Decimal)",
            "shr64 (Binary)",
            "shr64 (Hex)",
        ]

        shr64_value = n >> r
        table.add_row(
            [
                n,
                r,
                format(n, "064b"),
                format(r, "064b"),
                shr64_value,
                format(shr64_value, "064b"),
                hex(shr64_value),
            ]
        )

        print(table)
        return n >> r


def compare_digests(digest, expected):
    if digest != expected:
        print("Error:")
        print("Got:")
        print(digest)
        print("Expected:")
        print(expected)
    else:
        print("Test case ok.")


def main():
    print("Testing the SHA-512 Python model.")
    print("---------------------------------")

    # Create the plaintext message
    # plaintext = "21L5180-Amna Shabbir-35202-6513340-8"
    plaintext = "21L-6195-Muhammad Mahad-35202-9579091-5"
    print(f'Plaintext: "{plaintext}"')

    # printing plain text in ASCII and binary format
    print("Plaintext in ASCII and binary format:")
    table = PrettyTable()
    table.field_names = ["Character", "ASCII", "Binary"]

    for char in plaintext:
        table.add_row([char, ord(char), format(ord(char), "08b")])

    print(table)

    print("The whole message in binary format:")
    print(" ".join([format(ord(char), "08b") for char in plaintext]))

    message_length_bits = len(plaintext) * 8
    print(f"The message length in bits: {len(plaintext)} * 8={message_length_bits}")
    print(
        "But we need to append 1 and 0s to the message to make it a multiple of 1024 bits.i.e., message length congruent to 896 mod 1024"
    )
    print(f"message_length {message_length_bits} mod 1024 = 896 ")
    num = 0
    if message_length_bits % 1024 == 896:
        print("Message length is congruent to 896 mod 1024")
    else:
        print("Message length is not congruent to 896 mod 1024")
        print(
            "Appending 1 and 0s to the message to make it a multiple of 1024 bits.i.e., message length congruent to 896 mod 1024"
        )

        num = 896 - (message_length_bits % 1024)
        print(f"we have to add {num} bits to the message")
        message_length_bits += num
        assert message_length_bits % 1024 == 896
        print(f"New message length in bits: {message_length_bits}")
    print(f"We are adding total {num} bits")
    print(f"Appending 1 at the end of the message")
    print(f"Following by {num-1} 0s")

    print("Converting message to block of binary numbers.")
    # Convert the message to a block
    block = [
        int.from_bytes(plaintext[i : i + 8].encode("utf-8"), "big")
        for i in range(0, len(plaintext), 8)
    ]
    table = PrettyTable()
    table.field_names = ["Block Index", "Block Value"]
    for i in range(len(block)):
        table.add_row([i, block[i]])
    print(table)
    # converting to binary

    print("Block:", block)
    while len(block) < 16:
        print("Appending 0")
        block.append(0)

    print(
        f"Appending the length of the message in bits {len(plaintext) * 8} at the end"
    )
    block[-1] = len(plaintext) * 8  # Append the length of the message in bits

    binaryBlock = [format(x, "064b") for x in block]
    table = PrettyTable()
    table.field_names = ["Word Index", "Integer Value", "Binary Value"]
    for i, word in enumerate(binaryBlock):
        table.add_row([f"word{i}", block[i], word])
    print(table)
    print(f"The binary block in string format: {''.join(binaryBlock)}")

    print("Creating the SHA-512 object.")
    my_sha512 = SHA512(mode="MODE_SHA_512", verbose=1)
    print("Initializing the SHA-512 object.")
    my_sha512.init()
    print("Init Done Processing the block.")
    my_sha512.next(block)
    my_digest = my_sha512.get_digest()
    print("Digest:", my_digest)


if __name__ == "__main__":
    sys.exit(main())
