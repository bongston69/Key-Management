import sqlite3
from werkzeug.security import generate_password_hash

DATABASE_URI = 'instance/keys.db'  # SQLite database file


def create_admin(username, password):
    conn = sqlite3.connect(DATABASE_URI)
    cursor = conn.cursor()

    # Check if the user table exists, if not, create it
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT 0
    )
    ''')

    # Check if the user already exists
    cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
    if cursor.fetchone():
        print(f'User {username} already exists.')
        conn.close()
        return

    # Hash the password
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Insert the new admin user
    cursor.execute('INSERT INTO user (username, password, is_admin) VALUES (?, ?, ?)',
                   (username, hashed_password, True))
    conn.commit()
    conn.close()
    print(f'Admin user {username} created successfully.')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Create an admin user.')
    parser.add_argument('username', type=str, help='The username for the new admin user.')
    parser.add_argument('password', type=str, help='The password for the new admin user.')
    args = parser.parse_args()

    create_admin(args.username, args.password)
