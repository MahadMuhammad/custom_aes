""" 
Implementation of a custom AES algorithm variant named 'Pocket Algorithm'
developed for my Information Security course.
"""

from lib import substitute_nibbles


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
