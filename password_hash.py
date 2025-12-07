from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import argparse

ph = PasswordHasher()

def hash_password(pw):
    return ph.hash(pw)

def verify_password(stored_hash, candidate):
    try:
        ok = ph.verify(stored_hash, candidate)
        return ok
    except VerifyMismatchError:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argon2 password hash demo")
    parser.add_argument("--hash", action="store_true", help="Hash the provided password")
    parser.add_argument("--verify", action="store_true", help="Verify a password against a stored hash")
    parser.add_argument("--pw", required=True, help="Password")
    parser.add_argument("--stored", help="Stored hash (for verify)")
    args = parser.parse_args()

    if args.hash:
        print("Hash:", hash_password(args.pw))
    elif args.verify:
        if not args.stored:
            print("Provide --stored to verify against.")
        else:
            ok = verify_password(args.stored, args.pw)
            print("Verified:" if ok else "Invalid password")
    else:
        print("Use --hash or --verify. See --help.")
