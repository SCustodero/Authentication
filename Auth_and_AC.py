from CryptoProject import CryptoProject
from cryptography.fernet import Fernet
import sqlite3
from CryptoProject import CryptoProject as crypto
import os

# Password store for current user which is deleted at end of user session
global current_pass
current_pass = None

# Initialize CryptoProject class
crypto = CryptoProject()

class Authentication():
    def __init__(self):
        # Initialize database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Username and password table
        cursor.execute('CREATE TABLE IF NOT EXISTS users(\
                       username TEXT NOT NULL, \
                       password TEXT NOT NULL)')
        
        # ACL table
        cursor.execute('CREATE TABLE IF NOT EXISTS acl(doc_name TEXT NOT NULL, username TEXT NOT NULL)')

        conn.commit()
        
        conn.close()
        return
    
    def load_users(self):
        """Load users from persistent storage."""
        conn = sqlite3.connect('users.db')

        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')

        users = cursor.fetchall()

        conn.close()

        return users

    def save_users(self, users):
        # Insert new user into database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.executemany("INSERT INTO users VALUES(?, ?)", (users,))

        conn.commit()
        conn.close()
        return

    def create_account(self, users):
        username = input("Create a username: ")
        password = input("Create a password: ")
        
        # Check if username already exists
        for user in users:
            if user[0] == username:
                print("Username already exists.")
                return

        # Hash password
        hash = crypto.hash_string(password)
        
        # Generate RSA keys
        crypto.generate_rsa_keys(username)
        
        # Store RSA private key encrypted with AES
        with open(username + '_private.pem', 'r') as f:
            private_key = f.read()

        hidden_key = crypto.aes_encrypt(private_key, password)

        with open(username + '_private.pem', 'w') as f:
            f.write(hidden_key)

        # Save user to persistent storage
        data = (username, hash)
        self.save_users(data)
        return

    def login(self, users):
        global current_pass
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        # Check if username and password match
        for user in users:
            if user[0] == username:
                hash = user[1]
                if crypto.verify_integrity(password, hash):
                    print("Login successful.")
                    current_pass = password
                    return username
        print("Invalid login credentials")
        return False


class AccessControl():
    def __init__(self):
        return

    def load_acl(self):
        # Load ACL from persistent storage
        conn = sqlite3.connect('users.db')

        cursor = conn.cursor()
        cursor.execute('SELECT * FROM acl')

        acl = cursor.fetchall()

        conn.close()
        
        if acl:
            return acl
        return []

    def save_acl(self, acl):
        # Insert new document with associated user into database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.executemany("INSERT INTO acl VALUES(?, ?)", (acl, ))

        conn.commit()
        conn.close()
        return

    def create_file(self, username, acl):
        filename = input("Enter the name of the file you want to create: ")
        content = input("Enter content for the file: ")
        
        path = os.getcwd()

        # Create file with encypted content if it doesn't exist
        if not os.path.exists(path + "/" + filename + '.txt'):
            encrypted_content = crypto.rsa_encrypt(content, username)
            with open(filename + '.txt', 'w') as f:
                f.write(encrypted_content)
            new_acl = (filename, username)
            self.save_acl(new_acl)
            return

        # If file already exists, check if user has access
        for file in acl:
            if file[0] == filename:
                if file[1] == username:
                    break
                else:
                    print("You do not have access to this file.")
                    return

        # Ask if user wants to overwrite existing file that they own
        while True:
            overwrite = input("File already exists. Do you want to overwrite it? (y/n) ")
            if overwrite.lower() == 'y':
                encrypted_content = crypto.rsa_encrypt(content, username)
                with open(filename + '.txt', 'w') as f:
                    f.write(encrypted_content)
                new_acl = (filename, username)
                self.save_acl(new_acl)
                return
            elif overwrite.lower() == 'n':
                return
            else:
                print("Invalid input.")

    def read_file(self, username, acl):
        filename = input("Enter the name of the file you want to read: ")

        # Check if user has access        
        for file in acl:
            if file[0] == filename:
                if file[1] == username:
                    break
                else:
                    print("You do not have access to this file.")
                    return

        # Read decrypted file if user has access
        try:
            decrypted_content = crypto.rsa_decrypt(filename, username, current_pass)
            print(decrypted_content)
        except FileNotFoundError:
            print("File does not exist.")
            return

def main():
    global current_pass
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
                        ac.create_file(user, acl)
                        acl = ac.load_acl()
                    elif file_choice == '2':
                        ac.read_file(user, acl)
                    elif file_choice == '3':
                        print(f"Logging out {user}.")
                        current_pass = None
                        break
                    else:
                        print("Invalid choice.")
        elif choice == '3':
            current_pass = None
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()


"""
DATABASE SETUP: SQLite with two tables (users and acl)
PASSWORD STORE: Passwords are hashed and stored in the database
    This follows the Principle of Least Privilege because users do not have access to their own password
    Hashing passwords mitigates risk in case of a data breach
USER AND AC LISTS: Users and Access Control lists are stored in the database
    This follows the Principle of Least Privilege because only the program can edit these lists
    Using the database prevents attackers from editing the lists via creation of accounts or logins in the program
RSA KEYS: Keys are stored in files, and private keys are encrypted with AES using the user password
    This follows the Principle of Open Design because everything, including the files, are visible to any user, but 
        none are readable exepct through the proper user login
    This prevents an attacker from gaining access to the files and directly using the content because all important
        information is encrypted, including RSA keys using AES

"""