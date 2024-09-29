""" 
Implementation of a custom AES algorithm variant named 'Pocket Algorithm'
developed for my Information Security course.
"""

from lib import (
    substitute_nibbles_inverse,
    validate_text,
    shift_rows,
    mix_columns,
    gen_round_keys,
)


def main() -> None:
    plaintext: str = input("Enter the plaintext: (Press enter to use default value)")
    if not plaintext:
        plaintext = "903b"

    vplaintext = validate_text(plaintext, name="plaintext")

    # initially, we are just printing the things, that are mentioned in the document
    # Convert hex input to binary and remove the '0b' prefix
    plainTextBinary: str = bin(int(plaintext, 16))[2:]

    # (1) SubNibbles
    sub_nibbles = substitute_nibbles_inverse(plainTextBinary)
    subnibblesString = "".join(sub_nibbles)
    subnibblesBinary = bin(int(subnibblesString, 16))[2:]
    print(f"SubNibbles({plaintext}) = {subnibblesString}")

    # (2) ShiftRows
    #  In this step, the first row is rotated by four bits so that nibbles get swapped.
    # as from document, we need to shift row of input
    shiftRow = shift_rows(plainTextBinary)
    shiftRowString = "".join(shiftRow)
    print(f"ShiftRows({plaintext}) = {shiftRowString}")

    # (3) MixColumns
    # here, not sending the binary value, as it is not required
    mixCols = mix_columns(plainTextBinary)
    mixColsString = "".join(mixCols)
    print(f"MixColumns({plaintext}) = {mixColsString}")

    # Inputting key
    key: str = input("Enter a key: (Press enter to use default value)")
    if not key:
        key = "02cc"
    key = validate_text(key, name="key")

    keyBinary: str = bin(int(key, 16))[2:].zfill(16)
    roundK1, roundK2 = gen_round_keys(keyBinary)
    roundK1String: str = "".join([hex(int(x, 2))[2:] for x in roundK1])
    roundK2String: str = "".join([hex(int(x, 2))[2:] for x in roundK2])

    print(f"GenerateRoundKets({key}) = ({roundK1String}, {roundK2String})")


if __name__ == "__main__":
    main()
