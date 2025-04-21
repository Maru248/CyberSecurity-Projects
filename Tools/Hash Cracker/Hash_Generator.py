import hashlib


def generate_hash():
    text = input("Enter text to hash: ").strip()

    print("\nChoose a hashing algorithm:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA256")
    print("4. SHA512")

    try:
        choice = int(input("> ").strip())
        hash_func = {
            1: hashlib.md5,
            2: hashlib.sha1,
            3: hashlib.sha256,
            4: hashlib.sha512
        }.get(choice)

        if hash_func:
            hashed = hash_func(text.encode()).hexdigest()
            print(f"\n{hash_func.__name__.upper()} hash of '{text}':\n{hashed}\n")
        else:
            print("Invalid choice.")

    except ValueError:
        print("Invalid input. Please enter a number.")


if __name__ == "__main__":
    generate_hash()
