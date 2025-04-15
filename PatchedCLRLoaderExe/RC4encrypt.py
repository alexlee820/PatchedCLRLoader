import argparse

def rc4(key: bytes, data: bytes) -> bytes:
    """
    RC4 algorithm implementation.
    :param key: Key as bytes
    :param data: Data to encrypt/decrypt as bytes
    :return: Encrypted or decrypted data as bytes
    """
    S = list(range(256))
    j = 0
    out = bytearray()

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)

    return bytes(out)


def rc4_file(file_path: str, key: str, output_path: str) -> None:
    """
    Encrypt or decrypt a file using RC4.
    :param file_path: Path to the input file
    :param key: Encryption/Decryption key as a string
    :param output_path: Path to save the output file
    """
    with open(file_path, "rb") as input_file:
        file_bytes = input_file.read()

    # Convert the key to bytes
    key_bytes = key.encode()

    # Encrypt/Decrypt the file using RC4
    result_bytes = rc4(key_bytes, file_bytes)

    # Write the result to the output file
    with open(output_path, "wb") as output_file:
        output_file.write(result_bytes)


def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using RC4.")

    # Add arguments
    parser.add_argument("-i", "--input", type=str, required=True, help="Path to the input file.")
    parser.add_argument("-o", "--output", type=str, required=True, help="Path to the output file.")
    parser.add_argument("-k", "--key", type=str, required=True, help="Encryption/Decryption key.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    # Parse the arguments
    args = parser.parse_args()

    # Access the arguments
    input_file = args.input
    output_file = args.output
    key = args.key
    verbose = args.verbose

    # Verbose output
    if verbose:
        print(f"Input File: {input_file}")
        print(f"Output File: {output_file}")
        print(f"Key: {key}")
        print("Starting RC4 encryption/decryption...")

    # Perform RC4 encryption/decryption
    rc4_file(input_file, key, output_file)

    # Completion message
    if verbose:
        print("RC4 encryption/decryption completed successfully.")


if __name__ == "__main__":
    main()