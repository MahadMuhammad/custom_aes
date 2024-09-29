from d2 import perform_decryption


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
    # reverse of encode
    plainTextHex = bytes.fromhex("4765").decode("utf-8")
    print("Plain Text in Hex: ", plainTextHex)


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
    main()
