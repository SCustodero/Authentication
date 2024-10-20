from CryptoProject import CryptoProject
from cryptography.fernet import Fernet
import sqlite3
from CryptoProject import CryptoProject as crypto

# Initialize CryptoProject class
crypto = CryptoProject()

# File to store user accounts
# You can implement the backing store using a database or other methods as you like



class Authentication():
    def __init__(self):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        cursor.execute('CREATE TABLE IF NOT EXISTS users(\
                       username TEXT NOT NULL UNIQUE, \
                       password TEXT NOT NULL)')
        
        cursor.execute('CREATE TABLE IF NOT EXISTS acl(doc_name TEXT NOT NULL UNIQUE, username TEXT NOT NULL)')

        conn.commit()
        
        conn.close()
        return
    
    def load_users(self):
        """Load users from persistent storage."""
        try:
            conn = sqlite3.connect('users.db')

            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users')

            users = cursor.fetchall()

            conn.close()

            return users
        except FileNotFoundError:
            return {}

    def save_users(self, users):
        # Feed in a dictionary with keys of username and values of password
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.executemany("INSERT INTO users VALUES(:username, :password)", users)

        conn.commit()
        conn.close()
        return

    def create_account(self, users):
        
        # TODO: Implement account creation
        username = input("Create a username: ")
        password = input("Create a password: ")
        # TODO: Check if username already exists
        for user in users:
            if user[0] == username:
                print("Username already exists.")
                return
        # TODO: Store password securely
        hash = crypto.hash_string(password)

        crypto.generate_rsa_keys(username)

        # TODO: Save updated user list
        data = ({'username': username, 'password': hash},)
        self.save_users(data)
        return

    def login(self, users):
        username = input("Enter username: ")
        password = input("Enter password: ")
        # TODO: Implement login method including secure password check
        for user in users:
            if user[0] == username:
                hash = user[1]
                if crypto.verify_integrity(password, hash):
                    print("Login successful.")
                    return username
        print("Invalid login credentials")
        return False


class AccessControl():
    def __init__(self):
        return

    def load_acl(self):
        conn = sqlite3.connect('users.db')

        cursor = conn.cursor()
        cursor.execute('SELECT * FROM acl')

        acl = cursor.fetchall()

        conn.close()
        
        if acl:
            return acl
        # TODO: Load ACL (Access Control List) from persistent storage.
        return []

    def save_acl(self, acl):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.executemany("INSERT INTO acl VALUES(?, ?)", (acl, ))

        conn.commit()
        conn.close()
        #TODO: Save ACL to persistent storage.
        return

    def create_file(self, username):
        filename = input("Enter the name of the file you want to create: ")
        content = input("Enter content for the file: ")

        encrypted_content = crypto.rsa_encrypt(content, username)
        # TODO: Create the file and write content. EXTRA CREDIT: encrypt the file/content.
        with open(filename + '.txt', 'w') as f:
            f.write(encrypted_content)
        # TODO: Add file access entry in ACL

        acl = (filename, username)
        self.save_acl(acl)
        return



    def read_file(self, username, acl):
        filename = input("Enter the name of the file you want to read: ")

        for file in acl:
            if file[0] == filename:
                if file[1] == username:
                    break
                else:
                    print("You do not have access to this file.")
                    return

        decrypted_content = crypto.rsa_decrypt(filename, username)
        print(decrypted_content)
        
        # TODO: Check if the user has access. EXTRA CREDIT: If file was encrypted, decrypt the file/content

        # TODO: Optionally decrypt the file content


def main():
    auth = Authentication()
    ac = AccessControl()
    
    users = auth.load_users()
    acl = ac.load_acl()

    while True:
        print("\n--- Authentication & Access Control ---")
        print("1. Create an account")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            auth.create_account(users)
            users = auth.load_users()
        elif choice == '2':
            user = auth.login(users)
            if user:
                # If login is successful, show file options
                while True:
                    print("\n1. Create a file")
                    print("2. Read a file")
                    print("3. Logout")

                    file_choice = input("Enter your choice: ")
                    
                    if file_choice == '1':
                        ac.create_file(user)
                    elif file_choice == '2':
                        ac.read_file(user, acl)
                    elif file_choice == '3':
                        print(f"Logging out {user}.")
                        break
                    else:
                        print("Invalid choice.")
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
