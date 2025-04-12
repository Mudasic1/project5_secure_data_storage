# Secure Data Encryption System 🔐

A streamlined Streamlit application for securely storing and retrieving encrypted data with user authentication.

## 📑 Overview

This web application provides users with a secure platform to store sensitive information using modern encryption techniques. Users can register accounts, encrypt data with personal passkeys, and retrieve their data through proper authentication.

## 🌟 Features

- **Secure User Authentication** 👤
  - User registration and login with password hashing
  - Account lockout after multiple failed login attempts (security protection)
  - Session management using Streamlit's session state

- **Data Encryption** 🔒
  - Encrypts user data using Fernet symmetric encryption (AES-128)
  - Passkey-based encryption with PBKDF2 key derivation
  - Each piece of data is individually encrypted and can only be decrypted with its original passkey

- **User-Friendly Interface** 🖥️
  - Clean gradient background design
  - Intuitive navigation
  - Responsive error handling and user feedback
  - Copy functionality for encrypted data

- **Security Measures** 🛡️
  - Password hashing using PBKDF2 with SHA-256
  - Secure salt implementation
  - Temporary lockout after failed login attempts
  - No plaintext password storage

## 🛠️ Technologies Used

- **Python**: Core programming language
- **Streamlit**: Web application framework
- **Cryptography**: Python library for Fernet encryption
- **Hashlib**: For secure password hashing
- **JSON**: Local storage for user data

## 📋 Requirements

```
streamlit>=1.31.0
cryptography>=41.0.0
```

## 🔧 How It Works

1. **Registration**: Users create accounts with username and password
2. **Login**: Users authenticate to access their encrypted data
3. **Store Data**: Users enter data and create a unique passkey for that specific piece of information
4. **Retrieve Data**: Users can view their encrypted data and decrypt it by providing the original passkey

## 🔐 Security Implementation

- **Password Hashing**: User passwords are hashed using PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Data Encryption**: Uses Fernet symmetric encryption, which is built on AES-128-CBC with PKCS7 padding
- **Key Derivation**: Encryption keys are derived from user passkeys using PBKDF2
- **Security Lockout**: After 3 failed login attempts, users are locked out for 45 seconds

## 🖼️ UI Design

The application features a modern, gradient background design with:
- Clean user interface with responsive elements
- Visual feedback using emojis and color-coded messages
- Intuitive navigation through a sidebar menu
- Mobile-friendly layout

## 🚀 Future Enhancements

- Two-factor authentication
- Password strength requirements
- Export/import functionality for encrypted data
- Categorization and search for stored data
- Dark/light mode toggle

## ⚠️ Disclaimer

This project is for educational purposes. While it implements several security best practices, no system is 100% secure. For production environments, additional security measures would be recommended.



Created with ❤️ using Python and Streamlit
