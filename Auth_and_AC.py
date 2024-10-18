import json
from CryptoProject import CryptoProject
from cryptography.fernet import Fernet

# Initialize CryptoProject class
crypto = CryptoProject()

# File to store user accounts
# You can implement the backing store using a database or other methods as you like
USER_FILE = "users.json"
ACL_FILE = "acl.json"


# You must use the following two classes and their methods.  You can add methods, you can change the arguments coming into the methods, but you must use these classes and methods and do not change their names.

# To use the JSON files for backend storage, you can use the following functions:
# To write to a json file:
# with open('filename.json', 'w') as file:
#     json.dump(data, file)
# To read from a json file:
# with open('filename.json', 'r') as file:
#     data = json.load(file)
# See https://www.w3schools.com/python/python_json.asp for more information
# 
# NOTE: You need to figure out how you will use your JSON files to store user accounts and ACLs before you start coding your project.


class Authentication():
    def __init__(self):
        return
    
    def load_users(self):
        """Load users from persistent storage."""
        try:
            with open(USER_FILE, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save_users(self, users):
        # TODO: Save users to persistent storage.
        return

    def create_account(self, users):
        # TODO: Implement account creation
        username = input("Create a username: ")
        password = input("Create a password: ")
        # TODO: Check if username already exists

        # TODO: Store password securely
        
        # TODO: Save updated user list

        return

    def login(self, users):
        username = input("Enter username: ")
        password = input("Enter password: ")
        # TODO: Implement login method including secure password check

        return username


class AccessControl():
    def __init__(self):
        return

    def load_acl(self):
        # TODO: Load ACL (Access Control List) from persistent storage.
        return {}

    def save_acl(self, acl):
        #TODO: Save ACL to persistent storage.
        return

    def create_file(self, username, acl):
        filename = input("Enter the name of the file you want to create: ")
        content = input("Enter content for the file: ")

        # TODO: Create the file and write content. EXTRA CREDIT: encrypt the file/content.
        
        # TODO: Add file access entry in ACL
        return



    def read_file(self, username, acl):
        filename = input("Enter the name of the file you want to read: ")
        
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
