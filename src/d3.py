from d2 import perform_decryption
from lib import bitwise_xor, substitute_nibbles, gen_round_keys, mix_columns, shift_rows


def perform_encryption(block: str, key: str) -> str:
    """
    Perform encryption
    """
    # Round 1

    # SubNibbles
    substitueNibbles = substitute_nibbles(block)
    substitueNibbles = "".join(substitueNibbles)
    substitueNibbles = bin(int(substitueNibbles, 16))[2:].zfill(16)
    rk1, rk2 = gen_round_keys(key)
    rk1 = "".join(rk1)
    rk2 = "".join(rk2)

    # AddRoundKey
    rk1_xor_subNibbles = bitwise_xor(substitueNibbles, rk1)
    # MixCols
    mixCols = mix_columns(rk1_xor_subNibbles)
    mixCols = "".join(mixCols)
    mixCols = bin(int(mixCols, 16))[2:].zfill(16)
    # ShiftRows
    shiftRows = shift_rows(mixCols)
    shiftRows = "".join(shiftRows)
    shiftRows = bin(int(shiftRows, 16))[2:].zfill(16)

    # Round 2
    # SubNibbles
    substitueNibbles = substitute_nibbles(shiftRows)
    substitueNibbles = "".join(substitueNibbles)
    substitueNibbles = bin(int(substitueNibbles, 16))[2:].zfill(16)
    # Add rk2
    rk2_xor_subNibbles = bitwise_xor(substitueNibbles, rk2)
    # shiftRows
    shiftRows = shift_rows(rk2_xor_subNibbles)
    # the result is already in hex format no need to convert it

    cipherText = "".join(shiftRows)
    return cipherText
    # print(f"Debugging: {cipherText}")
    # exit()


def encryption():
    """
    Experimenting
    performing encryption
    """
    plainText = "Gentlemen, you can't fight in here. This is the war room."
    # make pair of 2 characters and if not pair add null padding
    if len(plainText) % 2 != 0:
        plainText += "\0"
    key = "149c"
    plainTextHex = plainText.encode("utf-8").hex()
    # Making a list four hex values to perform encryption with ease
    plainTextHexList = list()
    for i in range(0, len(plainTextHex), 4):
        plainTextHexList.append(plainTextHex[i : i + 4])

    # print(f"Plain Text: {plainTextHexList}")

    cipherText = str()
    for block in plainTextHexList:
        binaryBlock = bin(int(block, 16))[2:].zfill(16)
        binaryKey = bin(int(key, 16))[2:].zfill(16)
        # print(f"Block: {binaryBlock}")
        # print(f"Block: {binaryKey}")
        cipherText += f"{perform_encryption(binaryBlock, binaryKey)} "
    # reverse of encode
    # plainTextHex = bytes.fromhex(plainTextHex).decode("utf-8")
    # print("Plain Text in Hex: ", plainTextHex)
    print(f"Cipher Text: {cipherText}")


def main():
    file = "secret.txt"
    file_data = open(file, "r").read()
    print(f"Reading encrypted file {file}....")
    key = input("Enter the decryption key: (Press enter to use default value)")
    if not key:
        key = "149c"
        print(f"Using default key: {key}")

    keyBinary: str = bin(int(key, 16))[2:].zfill(16)

    # decrypting the ciphertext
    plainText = str()
    for block in file_data.split(" "):
        cipherTextBinary: str = bin(int(block, 16))[2:].zfill(16)
        plainTextHex = perform_decryption(cipherTextBinary, keyBinary)
        plainText += bytes.fromhex(plainTextHex).decode("utf-8")

    print(f"Decrypted Result\n{20*'-'}\n{plainText}\n{20*'-'}")


if __name__ == "__main__":
    encryption()
    main()
