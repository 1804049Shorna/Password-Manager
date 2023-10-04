import sqlite3
import bcrypt
import cryptography
from cryptography.fernet import Fernet
import json
import random
import string

# Initialize the database
def init_db():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            hashed_password TEXT
        )
    ''')
    # cursor.execute('''
    # ALTER TABLE passwords ADD COLUMN user_id INTEGER REFERENCES users (id)
    # ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            name TEXT,
            username TEXT,
            encrypted_password TEXT,
            encrypted_notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# Initialize the encryption key
def init_encryption_key():
    key = Fernet.generate_key()
    with open('encryption_key.key', 'wb') as key_file:
        key_file.write(key)

# Hash a master password during user registration
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Verify the user's master password during login
def verify_password(hashed_password, input_password):
    return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password)

# Encrypt data
def encrypt_data(data):
    with open('encryption_key.key', 'rb') as key_file:
        key = key_file.read()
    f = Fernet(key)
    return f.encrypt(data.encode())

# Decrypt data
def decrypt_data(encrypted_data):
    try:
        with open('encryption_key.key', 'rb') as key_file:
            key = key_file.read()
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode()
    except (FileNotFoundError, cryptography.fernet.InvalidToken) as e:
        print(f"Error decrypting data: {e}")
        return None

# Add a new user
def add_user(username, password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()

# Authenticate the user
def authenticate_user(username, password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT hashed_password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        hashed_password = result[0]
        return verify_password(hashed_password, password)
    else:
        return False

# Add a new entry
def add_entry(user_id, name, username, password, notes):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO passwords (user_id, name, username, encrypted_password, encrypted_notes)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, name, username, encrypt_data(password), encrypt_data(notes)))
    conn.commit()
    conn.close()

# Retrieve password by name
def get_password_by_name(user_id, name):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE user_id = ? AND name = ?', (user_id, name,))
    entry = cursor.fetchone()
    conn.close()
    if entry:
        return {
            'name': entry[2],
            'username': entry[3],
            'password': decrypt_data(entry[4]),
            'notes': decrypt_data(entry[5])
        }
    else:
        return None

# Delete an entry by name
def delete_entry(user_id, name):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE user_id = ? AND name = ?', (user_id, name,))
    conn.commit()
    conn.close()

# Export password data to a JSON file
def export_data(user_id, filename):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name, username, encrypted_password, encrypted_notes FROM passwords WHERE user_id = ?', (user_id,))
    data = [{'name': row[0], 'username': row[1], 'password': decrypt_data(row[2]), 'notes': decrypt_data(row[3])} for row in cursor.fetchall()]
    conn.close()
    with open(filename, 'w') as file:
        json.dump(data, file)

def generate_password():
    length = 12  # You can adjust the length as needed
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Import password data from a JSON file
def import_data(user_id, filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        for entry in data:
            add_entry(user_id, entry['name'], entry['username'], entry['password'], entry['notes'])
        return True
    except FileNotFoundError:
        return False

if __name__ == '__main__':
    init_db()
    init_encryption_key()

    while True:
        print('\nPassword Manager Menu:')
        print('1. Register')
        print('2. Login')
        print('3. Add Password')
        print('4. Retrieve Password')
        print('5. Delete Password')
        print('6. Export Data')
        print('7. Import Data')
        print('8. Generate Password ')
        print('9. Quit')

        choice = input('Enter your choice: ')

        if choice == '1':
            username = input('Enter a username: ')
            password = input('Enter a master password: ')
            add_user(username, password)
            print('User registered successfully!')

        elif choice == '2':
            username = input('Enter your username: ')
            password = input('Enter your master password: ')
            if authenticate_user(username, password):
                print('Authentication successful!')
                user_id = username  # You can use the username as a user ID for simplicity in this example
            else:
                print('Authentication failed.')

        elif choice == '3':
            if 'user_id' not in locals():
                print('Please login first.')
                continue
            name = input('Enter the name: ')
            username = input('Enter the username: ')
            password = input('Enter the password: ')
            notes = input('Enter optional notes: ')
            add_entry(user_id, name, username, password, notes)
            print('Password added successfully!')

        elif choice == '4':
            if 'user_id' not in locals():
                print('Please login first.')
                continue
            name = input('Enter the name to retrieve: ')
            entry = get_password_by_name(user_id, name)
            if entry:
                print(f'Name: {entry["name"]}')
                print(f'Username: {entry["username"]}')
                print(f'Password: {entry["password"]}')
                print(f'Notes: {entry["notes"]}')
            else:
                print('Password not found.')


        elif choice == '5':
            if 'user_id' not in locals():
                print('Please login first.')
                continue
            name = input('Enter the name to delete: ')
            delete_entry(user_id, name)
            print('Password deleted successfully!')

        elif choice == '6':
            if 'user_id' not in locals():
                print('Please login first.')
                continue
            filename = input('Enter the filename for export: ')
            export_data(user_id, filename)
            print('Data exported successfully!')

        elif choice == '7':
            if 'user_id' not in locals():
                print('Please login first.')
                continue
            filename = input('Enter the filename for import: ')
            success = import_data(user_id, filename)
            if success:
                print('Data imported successfully!')
            else:
                print('File not found or invalid format.')
                
        elif choice == '8':
            if 'user_id' not in locals():
                print('Please login first.')
                continue
            name = input('Enter the name: ')
            username = input('Enter the username: ')
            generate = input('Generate a strong password? (yes/no): ')
            if generate.lower() == 'yes':
                password = generate_password()
                print(f'Generated Password: {password}')
            else:
                password = input('Enter the password: ')
            notes = input('Enter optional notes: ')
            add_entry(user_id, name, username, password, notes)
            print('Password added successfully!')        

        elif choice == '9':
            break

        else:
            print('Invalid choice. Please try again.')

    print('Goodbye!')