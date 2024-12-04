from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
import os
import time

# Define constants
RUNS = 10
KEY_SIZES = {
    "RSA": [1024, 2048, 3072, 4096],
    "DSA": [1024, 2048, 3072],
    "ECC": [ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
}
def compute_average(times):
    if len(times) > 1:
        return sum(times[1:]) / (len(times) - 1)
    return times[0]  # If only one time is recorded, return it

def measure_key_gen_time(algorithm, key_size):
    times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        if algorithm == "RSA":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        elif algorithm == "DSA":
            private_key = dsa.generate_private_key(key_size=key_size)
        elif algorithm == "ECC":
            private_key = ec.generate_private_key(key_size)
        _ = private_key.public_key()  # Generate public key
        end = time.perf_counter()
        times.append(end - start)
    return compute_average(times)


def encrypt_message(public_key, message, chunk_size):
    encrypted_chunks = []
    for chunk in split_message(message, chunk_size):
        encrypted_chunks.append(public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return encrypted_chunks

def decrypt_message(private_key, encrypted_chunks):
    decrypted_chunks = []
    for chunk in encrypted_chunks:
        decrypted_chunks.append(private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return b"".join(decrypted_chunks)

def split_message(message, chunk_size):
    return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]


def measure_rsa_encrypt_decrypt_times(private_key, public_key, plaintext, chunk_size):
    encrypt_times = []
    decrypt_times = []

    for _ in range(RUNS):
        start_encrypt = time.perf_counter()
        ciphertext = encrypt_message(public_key, plaintext, chunk_size)
        end_encrypt = time.perf_counter()
        encrypt_times.append(end_encrypt - start_encrypt)

        start_decrypt = time.perf_counter()
        decrypted_text = decrypt_message(private_key, ciphertext)
        end_decrypt = time.perf_counter()
        decrypt_times.append(end_decrypt - start_decrypt)

    avg_encrypt_time = compute_average(encrypt_times)
    avg_decrypt_time = compute_average(decrypt_times)

    return avg_encrypt_time, avg_decrypt_time


def measure_signing_times(private_key, message, algorithm):
    signing_times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        if algorithm == "RSA":
            _ = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif algorithm == "DSA":
            _ = private_key.sign(
                message,
                hashes.SHA256()
            )
        elif algorithm == "ECC":
            _ = private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
        end = time.perf_counter()
        signing_times.append(end - start)
    return compute_average(signing_times)


def measure_verification_times(public_key, signature, message, algorithm):
    verification_times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        if algorithm == "RSA":
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif algorithm == "DSA":
            public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
        elif algorithm == "ECC":
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError(f"Unsupported key type: {algorithm}")
        end = time.perf_counter()
        verification_times.append(end - start)
    return compute_average(verification_times)



# Main execution
long_plaintext = os.urandom(10 * 1024)  # 10 KB plaintext
message = os.urandom(1000000)  # 1 MB message

# Keypair Generation
print(f"\n\t\tKeypair Generation Results")
for key_type, sizes in KEY_SIZES.items():
    for size in sizes:
        avg_time = measure_key_gen_time(key_type, size)
        print(f"{key_type} Keypair Generation ({size}-bit): {avg_time:.4f} seconds")

# RSA-specific operations
RSA_private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
RSA_public_key = RSA_private_key.public_key()

RSA_avg_encrypt_time, RSA_avg_decrypt_time = measure_rsa_encrypt_decrypt_times(
    RSA_private_key, RSA_public_key, long_plaintext, 32
)
print(f"\n\t\tRSA Encryption/Decryption Results")
print(f"RSA Encryption (100 iterations): {RSA_avg_encrypt_time:.4f} seconds")
print(f"RSA Decryption (100 iterations): {RSA_avg_decrypt_time:.4f} seconds")

# Signing and Verification
print(f"\n\t\tDigital Signing and Verification Results")
for key_type, sizes in KEY_SIZES.items():
    if key_type == "RSA":
        private_key, public_key = RSA_private_key, RSA_public_key
    else:
        size = sizes[0]  # Example: Use the first key size
        if key_type == "DSA":
            private_key = dsa.generate_private_key(key_size=size)
        elif key_type == "ECC":
            private_key = ec.generate_private_key(size)
        public_key = private_key.public_key()

    avg_signing_time = measure_signing_times(private_key, message, key_type)
    



    if key_type == "RSA":
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif key_type == "DSA":
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )
    elif key_type == "ECC":
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    avg_verification_time = measure_verification_times(public_key, signature, message, key_type)
    print(f"{key_type} Signing (100 iterations): {avg_signing_time:.4f} seconds")
    print(f"{key_type} Verification (100 iterations): {avg_verification_time:.4f} seconds")


    
