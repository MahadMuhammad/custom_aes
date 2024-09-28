""" 
Implementation of a custom AES algorithm variant named 'Pocket Algorithm'
developed for my Information Security course.
"""


def substitute_nibbles(plainTextBinary: str) -> list:
    """
    substituting each nibble in the block with a different one
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


def main() -> None:
    plaintext: str = input("Enter the plaintext: ")
    # 16 bits of input data
    # See this for more details: https://en.wikipedia.org/wiki/Nibble
    if len(plaintext) > 4:
        raise ValueError("The input should be less than or equal to 4 characters long")
    elif len(plaintext) < 4:
        # Padding the input with zeros
        plaintext = plaintext.ljust(4, "0")

    assert len(plaintext) == 4

    # Convert hex input to binary and remove the '0b' prefix
    plainTextBinary: str = bin(int(plaintext, 16))[2:]

    sub_nibbles = substitute_nibbles(plainTextBinary)
    subnibblesString = "".join(sub_nibbles)
    subnibblesBinary = bin(int(subnibblesString, 16))[2:]
    print(f"SubNibbles({plaintext}) = {subnibblesString}")


if __name__ == "__main__":
    main()
