import streamlit as st
from cryptography.fernet import Fernet

# --- Generate or enter a key ---
st.title("🔐 Secure Data Encryption System")

st.markdown("This app encrypts and decrypts messages using a secret key.")

# Key generation and input
option = st.radio("Choose a key option:", ["Generate Key", "Enter Key Manually"])

if option == "Generate Key":
    key = Fernet.generate_key()
    st.success("Key generated successfully!")
else:
    key = st.text_input("Enter your 32-byte base64-encoded key:")

# Encryption and decryption functions
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(token, key):
    fernet = Fernet(key)
    return fernet.decrypt(token.encode()).decode()

# User input
text_option = st.radio("Choose an operation:", ["Encrypt", "Decrypt"])

input_text = st.text_area("Enter your message/token:")

if st.button("Submit"):
    try:
        if isinstance(key, str):
            key = key.encode()
        if text_option == "Encrypt":
            encrypted = encrypt_message(input_text, key)
            st.success("Encrypted Message:")
            st.code(encrypted)
        else:
            decrypted = decrypt_message(input_text, key)
            st.success("Decrypted Message:")
            st.code(decrypted)
    except Exception as e:
        st.error(f"Error: {e}")
