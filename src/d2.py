""" 
For encryption and decryption of data
"""

from lib import (
    mix_columns_reverse,
    validate_text,
    shift_rows,
    gen_round_keys,
    bitwise_xor,
    substitute_nibbles_inverse,
)


def perform_decryption(cipherText: str, key: str) -> str:
    """
    function to perform decryption

    The workflow for decryption in PocketAES is to back-track the encryption process.
    - ShifRow is a self-inverse function, because rotating another time by 4 bits restores the
    original row.
    - XOR addition is also its own inverse, i.e. upon re-adding the same key you get back the
    original block.
    - For inverting SubNibbles, use the Table 1 but apply the opposite substitutions.
    - For inverting MixColumns, multiply each column with the inverse of the given constant
    matrix.
    """

    # ShiftRows
    shiftRow = shift_rows(cipherText)
    shiftRow = "".join(shiftRow)
    shiftRow = bin(int(shiftRow, 16))[2:].zfill(16)

    rk1, rk2 = gen_round_keys(key)
    rk1: str = "".join(rk1)
    rk2: str = "".join(rk2)

    roundKey_xor_data: str = bitwise_xor(shiftRow, rk2)

    # SubNibbles
    substitueNibbles = substitute_nibbles_inverse(roundKey_xor_data)
    substitueNibbles = "".join(substitueNibbles)
    substitueNibbles = bin(int(substitueNibbles, 16))[2:].zfill(16)

    # Round2
    shiftRow = shift_rows(substitueNibbles)
    shiftRow = "".join(shiftRow)
    mixCols = mix_columns_reverse(shiftRow)
    mixCols = "".join(mixCols)
    mixCols = bin(int(mixCols, 16))[2:].zfill(16)
    roundKey_xor_MixCols = bitwise_xor(mixCols, rk1)
    substitueNibbles = substitute_nibbles_inverse(roundKey_xor_MixCols)

    plainText = [hexValue for hexValue in substitueNibbles]

    return "".join(plainText)


def main() -> None:
    """
    main function for encryption and decryption
    """
    cipherText: str = input(
        "Enter the ciphertext block: (Press enter to use default value)"
    )
    if not cipherText:
        cipherText = "f3d7"
        print(f"Using default ciphertext: {cipherText}")
    # validate the input
    cipherText = validate_text(cipherText, name="ciphertext")

    key = input("Enter the key: (Press enter to use default value)")
    if not key:
        key = "40ee"
        print(f"Using default key: {key}")
    # validate the input
    key = validate_text(key, name="key")

    keyBinary: str = bin(int(key, 16))[2:].zfill(16)
    cipherTextBinary: str = bin(int(cipherText, 16))[2:].zfill(16)

    # decrypting the ciphertext
    plainText = perform_decryption(cipherTextBinary, keyBinary)

    print(f"Decrypted Block: {plainText}")


if __name__ == "__main__":
    main()
