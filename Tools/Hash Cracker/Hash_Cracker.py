"IMPORTANT NOTE: When you use this tool you will have to provide YOUR OWN WORDLIST!!"


import hashlib
import pyfiglet
from tqdm import tqdm

# Banner
ascii_banner = pyfiglet.figlet_format("HASH CRACKER")
print(ascii_banner)

# User input
wordlist_location = input('Enter wordlist file location: ').strip()
hash_input = input('Enter hash to be cracked: ').strip().lower()

# Supported hash functions
algorithms = {
    1: ('MD5', hashlib.md5),
    2: ('SHA1', hashlib.sha1),
    3: ('SHA256', hashlib.sha256),
    4: ('SHA512', hashlib.sha512)
}

# Crack function
def crack_hash(algorithm_name, hash_func):
    try:
        with open(wordlist_location, 'r', encoding='utf-8', errors='ignore') as f:
            total_lines = sum(1 for _ in f)

        with open(wordlist_location, 'r', encoding='utf-8', errors='ignore') as file:
            for line in tqdm(file, total=total_lines, desc=f"Cracking using {algorithm_name}"):
                word = line.strip()
                hashed_pass = hash_func(word.encode()).hexdigest()
                if hashed_pass == hash_input:
                    print("\n***************************")
                    print(f"Found cleartext password: {word}")
                    print(f"Hash matched using {algorithm_name}")
                    print("***************************\n")
                    return
        print(f"Password not found in the wordlist using {algorithm_name}.")
    except FileNotFoundError:
        print(f"Error: File '{wordlist_location}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Algorithm selection
print("Select hashing algorithm:")
for k, v in algorithms.items():
    print(f"{k}. {v[0]}")

try:
    selection = int(input("> ").strip())
    if selection in algorithms:
        name, func = algorithms[selection]
        crack_hash(name, func)
    else:
        print("Invalid selection.")
except ValueError:
    print("Please enter a valid number.")