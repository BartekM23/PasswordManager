import random
import string
import math

PEPPER = "RytD35$toyu35t"
NUM_OF_ITER = 10000

def make_salt():
    salt = ""
    for i in range(16):
        salt += random.choice(string.printable)
    return salt


def is_password_strong_entropy(password):
    digit = False
    lower = False
    upper = False
    special = False
    for char in password:
        if char in string.ascii_uppercase:
            upper = True
        elif char in string.ascii_lowercase:
            lower = True
        elif char in string.digits:
            digit = True
        elif char in string.punctuation:
            special = True
    pool = 0
    if digit:
        pool += 10
    if lower:
        pool += 26
    if upper:
        pool += 26
    if special:
        pool += 26
    entropy = len(password) * math.log(pool, 2)

    if entropy < 30:
        return False
    return True




