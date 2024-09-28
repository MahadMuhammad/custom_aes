""" 
Implementation of a custom AES algorithm variant named 'Pocket Algorithm'
developed for my Information Security course.
"""

from lib import substitute_nibbles, validate_plain_text, shift_rows


def main() -> None:
    plaintext: str = input("Enter the plaintext: ")
    validate_plain_text(plaintext)

    # initially, we are just printing the things, that are mentioned in the document
    # Convert hex input to binary and remove the '0b' prefix
    plainTextBinary: str = bin(int(plaintext, 16))[2:]

    # (1) SubNibbles
    sub_nibbles = substitute_nibbles(plainTextBinary)
    subnibblesString = "".join(sub_nibbles)
    subnibblesBinary = bin(int(subnibblesString, 16))[2:]
    print(f"SubNibbles({plaintext}) = {subnibblesString}")

    # (2) ShiftRows
    #  In this step, the first row is rotated by four bits so that nibbles get swapped.
    # as from document, we need to shift row of input
    shiftRow = shift_rows(plainTextBinary)
    shiftRowString = "".join(shiftRow)
    print(f"ShiftRows({plaintext}) = {shiftRowString}")


if __name__ == "__main__":
    main()
