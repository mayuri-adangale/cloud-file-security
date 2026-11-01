import streamlit as st
import os
import io
import zipfile
import hashlib
import boto3
from cryptography.fernet import Fernet

st.set_page_config(page_title="Secure Cloud File Storage", page_icon="🔒", layout="centered")

st.markdown("""
<style>
#MainMenu, footer, header {visibility: hidden;}
.block-container {padding-top: 2rem; max-width: 820px;}
.hero {
    background: linear-gradient(135deg, #13264A 0%, #1E3A6E 100%);
    border: 1px solid #2A4A85;
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 24px;
}
.hero h1 {margin: 0; font-size: 2rem; color: #FFFFFF;}
.hero p {margin: 8px 0 0 0; color: #A9BCDD; font-size: 1rem;}
.badges span {
    display: inline-block;
    background: #0B1730;
    border: 1px solid #2A4A85;
    color: #38BDF8;
    border-radius: 999px;
    padding: 4px 12px;
    margin: 14px 8px 0 0;
    font-size: 0.8rem;
}
div.stButton > button, div.stDownloadButton > button {
    width: 100%;
    border-radius: 10px;
    border: 1px solid #38BDF8;
    background: #13264A;
    color: #E6EDF7;
    padding: 0.6rem 1rem;
    font-weight: 600;
}
div.stButton > button:hover, div.stDownloadButton > button:hover {
    background: #38BDF8;
    color: #0B1730;
    border-color: #38BDF8;
}
</style>

<div class="hero">
    <h1>🔒 Secure Cloud File Storage</h1>
    <p>Split, encrypt and store files on AWS S3, then download and verify them.</p>
    <div class="badges">
        <span>Fernet encryption</span>
        <span>1 MB block splitting</span>
        <span>SHA-256 integrity check</span>
        <span>Amazon S3</span>
    </div>
</div>
""", unsafe_allow_html=True)

# --- CONFIGURATION ---
AWS_BUCKET_NAME = "mayuri-cloud-project-0099"
AWS_REGION = "ap-southeast-2"
CHUNK_SIZE = 1024 * 1024  # 1 MB per block


def get_secret(name):
    """Read a value from Streamlit secrets (online). Returns None if not set (local run)."""
    try:
        return st.secrets[name]
    except Exception:
        return None


# S3 client: uses Streamlit secrets online, or your saved AWS CLI keys locally
access_key = get_secret("AWS_ACCESS_KEY_ID")
secret_key = get_secret("AWS_SECRET_ACCESS_KEY")
if access_key and secret_key:
    s3_client = boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )
else:
    s3_client = boto3.client("s3", region_name=AWS_REGION)


def get_key():
    """Encryption key: from Streamlit secrets online, or secret.key file locally."""
    secret_fernet_key = get_secret("FERNET_KEY")
    if secret_fernet_key:
        return secret_fernet_key.encode()
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
        return key
    with open("secret.key", "rb") as f:
        return f.read()


cipher = Fernet(get_key())


def list_block_keys(prefix):
    paginator = s3_client.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=AWS_BUCKET_NAME, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith(".enc"):
                keys.append(obj["Key"])
    keys.sort()
    return keys


uploaded_file = st.file_uploader("Choose a file to secure", type=["txt", "pdf", "png", "jpg"])

if uploaded_file is not None:
    st.success(f"File '{uploaded_file.name}' ready for processing!")
    prefix = f"chunks/{uploaded_file.name}/"

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔐 Encrypt, Split & Upload to S3"):
            try:
                data = uploaded_file.getvalue()
                original_hash = hashlib.sha256(data).hexdigest()

                # 1. Split into blocks
                blocks = [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
                st.info(f"File size: {len(data)} bytes, split into {len(blocks)} block(s)")

                progress = st.progress(0)
                for index, block in enumerate(blocks, start=1):
                    # 2. Encrypt each block
                    encrypted_block = cipher.encrypt(block)
                    # 3. Upload each block
                    chunk_key = f"{prefix}part_{index:05d}.enc"
                    s3_client.put_object(Bucket=AWS_BUCKET_NAME, Key=chunk_key, Body=encrypted_block)
                    st.write(f"Uploaded `{chunk_key}`")
                    progress.progress(index / len(blocks))

                # Save hash of original file for integrity check
                s3_client.put_object(Bucket=AWS_BUCKET_NAME, Key=f"{prefix}hash.txt", Body=original_hash.encode())

                st.success(f"File split into {len(blocks)} encrypted blocks and uploaded to S3!")
                st.code(f"SHA-256 of original: {original_hash}")
            except Exception as e:
                st.error(f"S3 Upload Error: {e}")

    with col2:
        if st.button("🔓 Download from S3 & Decrypt"):
            try:
                keys = list_block_keys(prefix)
                if not keys:
                    st.error("No blocks found in S3. Upload the file first.")
                else:
                    st.info(f"Found {len(keys)} encrypted block(s) in S3")
                    progress = st.progress(0)
                    restored = b""
                    for index, chunk_key in enumerate(keys, start=1):
                        # Download and decrypt each block, then merge
                        enc_block = s3_client.get_object(Bucket=AWS_BUCKET_NAME, Key=chunk_key)["Body"].read()
                        restored += cipher.decrypt(enc_block)
                        progress.progress(index / len(keys))

                    restored_hash = hashlib.sha256(restored).hexdigest()
                    original_hash = s3_client.get_object(
                        Bucket=AWS_BUCKET_NAME, Key=f"{prefix}hash.txt"
                    )["Body"].read().decode()

                    if restored_hash == original_hash:
                        st.success("File downloaded, decrypted and merged. Integrity check PASSED (hashes match)!")
                    else:
                        st.error("Integrity check FAILED: hashes do not match.")
                    st.code(f"SHA-256 of restored: {restored_hash}")

                    st.download_button(
                        "📥 Download Restored File",
                        data=restored,
                        file_name=f"restored_{uploaded_file.name}",
                    )
            except Exception as e:
                st.error(f"S3 Download Error: {e}")

    st.write("")
    if st.button("📦 Download Encrypted Blocks (ZIP)"):
        try:
            keys = list_block_keys(prefix)
            if not keys:
                st.error("No blocks found in S3. Upload the file first.")
            else:
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                    for chunk_key in keys:
                        enc_block = s3_client.get_object(Bucket=AWS_BUCKET_NAME, Key=chunk_key)["Body"].read()
                        zf.writestr(chunk_key.split("/")[-1], enc_block)
                st.success(f"Downloaded {len(keys)} blocks from S3 in encrypted form (not decrypted).")
                st.download_button(
                    "📥 Save Encrypted Blocks (ZIP)",
                    data=zip_buffer.getvalue(),
                    file_name=f"{uploaded_file.name}_encrypted_blocks.zip",
                )
        except Exception as e:
            st.error(f"S3 Download Error: {e}")