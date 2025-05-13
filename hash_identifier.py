import re

def identify_hash(hash_str):
    # Strip and normalize
    hash_str = hash_str.strip()

    # Common hash formats with their lengths and patterns
    hash_patterns = [
        ("MD5", re.compile(r"^[a-fA-F0-9]{32}$")),
        ("SHA-1", re.compile(r"^[a-fA-F0-9]{40}$")),
        ("SHA-256", re.compile(r"^[a-fA-F0-9]{64}$")),
        ("SHA-512", re.compile(r"^[a-fA-F0-9]{128}$")),
        ("bcrypt", re.compile(r"^\$2[abyx]\$\d{2}\$[./A-Za-z0-9]{53}$")),
        ("scrypt", re.compile(r"^\$scrypt\$.*")),
        ("Argon2", re.compile(r"^\$argon2(id|i|d)\$.*")),
        ("Unix crypt (SHA-512)", re.compile(r"^\$6\$.*")),
        ("Unix crypt (MD5)", re.compile(r"^\$1\$.*")),
        ("Unix crypt (Blowfish)", re.compile(r"^\$2[aby]\$.*")),
    ]

    # Try all patterns
    for name, pattern in hash_patterns:
        if pattern.match(hash_str):
            return name

    # Fallback on length
    hash_len = len(hash_str)
    if hash_len == 32:
        return "Possibly MD5"
    elif hash_len == 40:
        return "Possibly SHA-1"
    elif hash_len == 64:
        return "Possibly SHA-256"
    elif hash_len == 128:
        return "Possibly SHA-512"
    else:
        return "Unknown or custom hash format"

def main():
    hash_input = input("Enter the hash to identify: ")
    hash_type = identify_hash(hash_input)
    print(f"Identified hash type: {hash_type}")

if __name__ == "__main__":
    main()
