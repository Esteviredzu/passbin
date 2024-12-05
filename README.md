# Password Manager

A simple password manager that allows you to store and retrieve passwords securely. The application uses encryption to store login credentials, ensuring privacy and protection for your sensitive data.

## Features

- **Create a new password database**: Create a secure password file protected by a master password.
- **Add new passwords**: Add new login credentials with encryption.
- **View stored passwords**: View stored passwords by providing the master password.
- **Generate random passwords**: Generate random passwords of customizable lengths.

## Requirements

- Python 3.x
- The `cryptography` library for encryption and decryption.
- The `pickle` library for serializing and deserializing data.

To install the necessary dependencies, run:

```bash
pip install cryptography
