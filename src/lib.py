""" 
functions used in the main program
"""

# From the given document
sBox: dict = {
    "0000": "1010",
    "0001": "0000",
    "0010": "1001",
    "0011": "1110",
    "0100": "0110",
    "0101": "0011",
    "0110": "1111",
    "0111": "0101",
    "1000": "0001",
    "1001": "1101",
    "1010": "1100",
    "1011": "0111",
    "1100": "1011",
    "1101": "0100",
    "1110": "0010",
    "1111": "1000",
}

constant_matrix = [
    [1, 4],
    [4, 1],
]


def substitute_nibbles(plainTextBinary: str) -> list:
    """
    substituting each nibble in the block with a different one
    """

    subNibbles: list[str] = list()
    if len(plainTextBinary) == 4:
        # input is a 4 bit nibble
        subNibbles.append(sBox[plainTextBinary])
    elif len(plainTextBinary) == 16:
        # splitting into 4 bit nibbles
        for i in range(0, 16, 4):
            subNibbles.append(sBox[plainTextBinary[i : i + 4]])
    else:
        raise ValueError("Invalid must be either 4 or 16 bits long")

    hexValues: list = list()

    for binaryValue in subNibbles:
        hexValue = hex(int(binaryValue, 2))[2:]
        hexValues.append(hexValue)

    return hexValues


def shift_rows(plainTextBinary: str) -> list:
    """
    performing shift row operation
    """
    # converting into nibbles for ease
    nibbles = [plainTextBinary[i : i + 4] for i in range(0, len(plainTextBinary), 4)]
    nibbles[0], nibbles[2] = nibbles[2], nibbles[0]

    # now. again converting into binary
    binaryValues: list = list()
    for value in nibbles:
        hexValue = hex(int(value, 2))[2:]
        binaryValues.append(hexValue)

    return binaryValues


def mix_columns(plainTextBinary: str) -> list:
    nibbles = [
        int(plainTextBinary[i : i + 4], 2) for i in range(0, len(plainTextBinary), 4)
    ]

    d0 = finite_field_multiply(
        (nibbles[0]), constant_matrix[0][0]
    ) ^ finite_field_multiply((nibbles[1]), constant_matrix[0][1])
    d1 = finite_field_multiply(
        (nibbles[0]), constant_matrix[1][0]
    ) ^ finite_field_multiply((nibbles[1]), constant_matrix[1][1])
    d2 = finite_field_multiply(
        (nibbles[2]), constant_matrix[0][0]
    ) ^ finite_field_multiply((nibbles[3]), constant_matrix[0][1])
    d3 = finite_field_multiply(
        (nibbles[2]), constant_matrix[1][0]
    ) ^ finite_field_multiply((nibbles[3]), constant_matrix[1][1])

    mixedCols: list = [hex(x)[2:] for x in [d0, d1, d2, d3]]

    return mixedCols


def finite_field_multiply(a: int, b: int):
    """
    finite field GF(2^4)
    """
    m = 0

    while b > 0:
        # checking the lsb of b
        if b & 1 == 1:
            m ^= a
        a <<= 1

        # checking if fourth bit is set
        if a & 0b10000:
            a ^= 0b10011
        b >>= 1

    return m


def gen_round_keys(binaryKey: str) -> tuple:
    # constants
    from typing import Final

    Rcon_1: Final[str] = "1110"
    Rcon_2: Final[str] = "1010"

    rk1 = list()
    rk2 = list()

    bkmatrix = [binaryKey[i : i + 4] for i in range(0, len(binaryKey), 4)]

    rk1.append(
        bitwise_xor(
            bitwise_xor(
                bkmatrix[0],
                bin(int(substitute_nibbles(bkmatrix[3])[0], 16))[2:].zfill(4),
            ),
            Rcon_1,
        )
    )
    for i in range(0, 3):
        rk1.append(bitwise_xor(bkmatrix[i + 1], rk1[i]))

    rk2.append(
        bitwise_xor(
            bitwise_xor(
                rk1[0],
                bin(int(substitute_nibbles(rk1[3])[0], 16))[2:].zfill(4),
            ),
            Rcon_2,
        )
    )
    for i in range(0, 3):
        rk2.append(bitwise_xor(rk1[i + 1], rk2[i]))

    return rk1, rk2


def bitwise_xor(a, b):
    if len(a) != len(b):
        raise ValueError("strings must have the same length for XOR operation")

    result = str()
    for bit1, bit2 in zip(a, b):
        result += "1" if bit1 != bit2 else "0"

    return result


# a slite redundancy in the code
def validate_key(key: str) -> None:
    if len(key) > 4:
        raise ValueError("The input should be less than or equal to 4 characters long")
    elif len(key) < 4:
        # Padding the input with zeros
        key = key.ljust(4, "0")

    assert len(key) == 4


def validate_plain_text(plaintext: str) -> None:
    """
    Validate the plain text input
    """
    # 16 bits of input data
    # See this for more details: https://en.wikipedia.org/wiki/Nibble
    if len(plaintext) > 4:
        raise ValueError("The input should be less than or equal to 4 characters long")
    elif len(plaintext) < 4:
        # Padding the input with zeros
        plaintext = plaintext.ljust(4, "0")

    assert len(plaintext) == 4
