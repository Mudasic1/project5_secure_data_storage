import streamlit as st
import hashlib
import json
import os
import time 
import base64
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# DATA INFORMATION OF USER 
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 45

# Add background gradient image with new colors
def add_bg_gradient():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(to right, #00b, #c93d);
        }
        .stApp > header {
            background-color: transparent;
        }
        .stTextInput, .stTextArea, .stButton>button, .stSelectbox>div>div {
            background-color: rgba(0, 0, 0, 0.9) !important;
        }
        h1, h2, h3 {
            color: white !important;
        }
        p {
            color: rgba(255, 255, 255, 0.9) !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

# Apply background
add_bg_gradient()
 
# SECTION LOGIN DETAILS 
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# DATA IS LOADING 
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            st.error("❌ Error reading data file. Creating a new one.")
            return {}
    return {}
    
def save_data(data):
    try:
        with open(DATA_FILE, "w") as f:
            json.dump(data, f)
        return True
    except Exception as e:
        st.error(f"❌ Error saving data: {str(e)}")
        return False

def generate_key(passkey):
    # Generate a key from the passkey
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    # Ensure the key is properly formatted for Fernet (32 bytes, base64-encoded)
    return base64.urlsafe_b64encode(key[:32] if len(key) > 32 else key.ljust(32, b'\0'))

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# cryptography.fernet used 
def encrypt_text(text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"❌ Encryption error: {str(e)}")
        return None

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        # Don't show the specific error to the user for security reasons
        return None
    
# Load data at startup
stored_data = load_data()

#  NAVIGATION 
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("📑 Navigation", menu)

# Check if the user is logged in for protected pages
def check_authentication():
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
        return False
    return True

if choice == "Home":
    st.subheader("👋 Welcome To My Data Encryption System Using Streamlit!")
    st.markdown("✨ Develop a Streamlit-based secure data storage and retrieval system where:"
               "\n- 🔑 Users store data with a unique passkey."
               "\n- 🔓 Users decrypt data by providing the correct passkey."
               "\n- ⚠️ Multiple failed attempts result in a forced reauthorization (login page)."
               "\n- 💾 The system operates entirely in memory without external databases.")
    
    # Show login status
    if st.session_state.authenticated_user:
        st.success(f"👤 Currently logged in as: {st.session_state.authenticated_user}")
        if st.button("📤 Logout"):
            st.session_state.authenticated_user = None
            st.success("✅ Logged out successfully!")
            st.experimental_rerun()

#  USER REGISTRATION 
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("👤 Choose Username")
    password = st.text_input("🔑 Choose Password", type="password")
    confirm_password = st.text_input("🔄 Confirm Password", type="password")

    if st.button("Register"):
        if not username or not password:
            st.error("❌ Both username and password are required.")
        elif password != confirm_password:
            st.error("❌ Passwords don't match!")
        elif username in stored_data:
            st.warning("⚠️ User already exists.")
        else:
            stored_data[username] = {
                "password": hash_password(password),
                "data": []
            }
            if save_data(stored_data):
                st.success("✅ User registered successfully!")
                # Auto login after registration
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.info("🔄 Redirecting to Home page...")
                time.sleep(1)
                st.experimental_rerun()

elif choice == "Login":
    st.subheader("🔑 User Login")

    # Check for lockout
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if st.button("Login"):
        if username and password:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome {username}!")
                # Redirect to home page after successful login
                time.sleep(1)
                st.experimental_rerun()
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid credentials. {remaining} attempts left.")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error(f"🔒 Too many failed attempts. Please wait {LOCKOUT_DURATION} seconds.")
                    st.stop()
        else:
            st.error("❌ Please enter both username and password.")

# === data store section ===
elif choice == "Store Data":
    if check_authentication():
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("📝 Enter data to store")
        passkey = st.text_input("🔑 Encryption key (passphrase)", type="password")
        confirm_passkey = st.text_input("🔄 Confirm encryption key", type="password")

        if st.button("🔒 Encrypt And Save"):
            if not data:
                st.error("❌ Please enter data to encrypt.")
            elif not passkey:
                st.error("❌ Please enter an encryption key.")
            elif passkey != confirm_passkey:
                st.error("❌ Encryption keys don't match!")
            else:
                encrypted = encrypt_text(data, passkey)
                if encrypted:
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    if save_data(stored_data):
                        st.success("✅ Data encrypted and stored successfully.")
                        # Clear inputs after successful operation
                        st.empty()
                else:
                    st.error("❌ Encryption failed. Please try a different key.")

# === data retrieve section ===
elif choice == "Retrieve Data":
    if check_authentication():
        st.subheader("🔑 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("📭 No encrypted data found. Store some data first!")
        
        else:
            st.write("🔒 Your Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.code(f"Entry #{i+1}: {item[:50]}..." if len(item) > 50 else item, language="text")
                with col2:
                    if st.button(f"📋 Copy #{i+1}", key=f"copy_{i}"):
                        # Create a temporary textarea to enable copying
                        st.code(item)
                        st.success("✅ Text copied to clipboard! Use Ctrl+C to copy.")
            
            st.subheader("🔓 Decrypt Your Data")
            option = st.radio("Select decryption method:", ["Select from my entries", "Enter encrypted text manually"])
            
            if option == "Select from my entries" and user_data:
                selected_index = st.selectbox("Choose entry to decrypt:", range(len(user_data)), 
                                             format_func=lambda i: f"Entry #{i+1}")
                encrypted_input = user_data[selected_index]
                st.code(f"Selected: {encrypted_input[:50]}..." if len(encrypted_input) > 50 else encrypted_input)
            else:
                encrypted_input = st.text_area("🔒 Enter Encrypted Text")
            
            passkey = st.text_input("🔑 Enter Passkey To Decrypt", type="password")

            if st.button("🔓 Decrypt"):
                if not encrypted_input:
                    st.error("❌ Please select or enter encrypted text.")
                elif not passkey:
                    st.error("❌ Please enter your passkey.")
                else:
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success("✅ Decryption successful!")
                        st.markdown("### 📄 Decrypted Data:")
                        st.markdown(f"```\n{result}\n```")
                    else:
                        st.error("❌ Decryption failed. Check your passkey or encrypted text.")