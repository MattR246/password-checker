import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}.')
    return res


def leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password.rstrip('\n'))
        if count:
            print(f'{password} was found {count} times! Time to retire that password.')
        else:
            print(f'{password} was not found. Carry on!')
    return 'Process complete.'


passwords = open('passwords.txt', mode='r').readlines()

if __name__ == '__main__':
    if passwords[0] == '\n':
        print('To test and see if your passwords have ever been included in a data breach, create a text (.txt) file '
              'called "passwords" in the same folder as this one. Inside of that file, put each password you want to '
              'check on a separate line.')
    else:
        sys.exit(main(passwords))
