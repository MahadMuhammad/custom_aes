""" 
For encryption and decryption of data

The workflow for decryption in PocketAES is to back-track the encryption process. 
- ShifRow is a self-inverse function, because rotating another time by 4 bits restores the 
original row. 
- XOR addition is also its own inverse, i.e. upon re-adding the same key you get back the 
original block. 
- For inverting SubNibbles, use the Table 1 but apply the opposite substitutions. 
- For inverting MixColumns, multiply each column with the inverse of the given constant 
matrix.
"""

from lib import validate_text


def main() -> None:
    """
    main function for encryption and decryption
    """
    cipherText: str = input(
        "Enter the ciphertext block: (Press enter to use default value)"
    )
    if not cipherText:
        cipherText = "f3d7"
    # validate the input
    cipherText = validate_text(cipherText, name="ciphertext")


if __name__ == "__main__":
    main()
