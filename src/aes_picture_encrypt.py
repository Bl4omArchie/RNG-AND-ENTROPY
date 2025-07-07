from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from dataclasses import dataclass
from PIL import Image

from io import BytesIO
import streamlit as st
import numpy as np
import os


@dataclass
class Picture:
    name: str
    path: str
    image: Image.Image
    data: np.ndarray
    data_bytes: bytes
    state: str

@dataclass
class EncryptedPicture:
    name: str
    path: str
    image: Image.Image
    data: np.ndarray
    data_bytes: bytes
    state: str
    iv: bytes
    key: bytes


def get_image(picture_path: str, format_file="RGBA") -> Picture:
    if os.path.isfile(picture_path):
        image = Image.open(picture_path).convert(format_file)
        data = np.array(image)
        data_bytes = data.tobytes()
        
        return Picture(os.path.splitext(os.path.basename(picture_path))[0], picture_path, image, data, data_bytes, "plaintext")
    
    else:
        return -1


class AES_interface:
    @staticmethod
    def pad_image(data):
        pad_len = 16 - (len(data) % 16)
        return data + b'\0' * pad_len

    @staticmethod
    def aes_encrypt(data, data_bytes, key, enc_file_path=None, iv_or_nonce=None, aes_mode=AES.MODE_ECB):
        if aes_mode in [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            cipher = AES.new(key, aes_mode, iv=iv_or_nonce) if iv_or_nonce else AES.new(key, aes_mode)
        elif aes_mode == AES.MODE_CTR:
            cipher = AES.new(key, aes_mode, nonce=iv_or_nonce)

        if aes_mode in [AES.MODE_ECB, AES.MODE_CBC]:
            padded_data = AES_interface.pad_image(data_bytes)
        else:
            padded_data = data_bytes

        encrypted_data = cipher.encrypt(padded_data)
        encrypted_array = np.frombuffer(encrypted_data[:len(data_bytes)], dtype=np.uint8)
        encrypted_array = encrypted_array.reshape(data.shape)
        encrypted_image = Image.fromarray(encrypted_array)

        if enc_file_path:
            encrypted_image.save(enc_file_path)

        return encrypted_image, encrypted_array

    @staticmethod
    def aes_decrypt(enc_img_array, key, dec_file_path=None, aes_mode=AES.MODE_ECB, iv_or_nonce=None):
        data_bytes = enc_img_array.tobytes()

        if aes_mode in [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            cipher = AES.new(key, aes_mode, iv=iv_or_nonce) if iv_or_nonce else AES.new(key, aes_mode)
        elif aes_mode == AES.MODE_CTR:
            cipher = AES.new(key, aes_mode, nonce=iv_or_nonce)

        decrypted_data = cipher.decrypt(data_bytes)
        decrypted_data = decrypted_data[:enc_img_array.size]
        decrypted_array = np.frombuffer(decrypted_data, dtype=np.uint8)
        decrypted_array = decrypted_array.reshape(enc_img_array.shape)

        decrypted_image = Image.fromarray(decrypted_array)
        
        if dec_file_path:
            decrypted_image.save(dec_file_path)
        
        return decrypted_image


class Picture_Encryption(AES_interface):
    def __init__(self, pictures: list[Picture], format_file="RGBA", storage_folder="pic/"):
        self.format_file = format_file
        self.storage_folder = storage_folder
        self.pictures = pictures
        self.enc_pictures = []
        os.makedirs(self.storage_folder, exist_ok=True)

    @classmethod
    def upload_folder(cls, folder: str, format_file="RGBA", storage_folder="pic/"):
        pics = []
        if os.path.exists(folder):
            for filename in os.listdir(folder):
                full_path = os.path.join(folder, filename)
                img = get_image(full_path, format_file)
                if img != -1:
                    pics.append(img)
        
        return cls(pics, format_file, storage_folder)

    def encrypt_pictures(self, aes_mode=AES.MODE_ECB) -> None:
        if not self.pictures:
            raise ValueError("Please upload pictures")

        for pic in self.pictures:
            key = get_random_bytes(16)

            if aes_mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
                iv_or_nonce = get_random_bytes(16)
            elif aes_mode == AES.MODE_CTR:
                iv_or_nonce = get_random_bytes(8)
            else:
                iv_or_nonce = None

            enc_path = os.path.join(self.storage_folder, f"{pic.name}_encrypted.png")
            enc_name = os.path.splitext(os.path.basename(enc_path))[0]

            encrypted_img = self.aes_encrypt(
                data=pic.data,
                data_bytes=pic.data_bytes,
                key=key,
                enc_file_path=enc_path,
                iv_or_nonce=iv_or_nonce,
                aes_mode=aes_mode
            )

            self.enc_pictures.append(EncryptedPicture(
                name=enc_name,
                path=enc_path,
                image=encrypted_img,
                data=np.array(encrypted_img),
                data_bytes=np.array(encrypted_img).tobytes(),
                state="encrypted",
                iv=iv_or_nonce,
                key=key
            ))

    def decrypt_pictures(self, aes_mode=AES.MODE_ECB) -> None:
        for pic in self.enc_pictures:
            dec_name = f"{pic.name}_decrypted.png"
            dec_path = os.path.join(self.storage_folder, dec_name)

            decrypted_img = self.aes_decrypt(
                enc_img_array=pic.data,
                key=pic.key,
                dec_file_path=dec_path,
                aes_mode=aes_mode,
                iv_or_nonce=pic.iv
            )

            self.pictures.append(Picture(
                name=dec_name,
                path=dec_path,
                image=decrypted_img,
                data=np.array(decrypted_img),
                data_bytes=np.array(decrypted_img).tobytes(),
                state="decrypted"
            ))

    def get_state(self) -> None:
        print("========================")
        for pic in self.pictures:
            print(f"{pic.name} : {pic.image.size} - {pic.state}")


@st.cache_data(show_spinner=False)
def process_uploaded_image(file_bytes, name, max_dim=512):
    image = Image.open(BytesIO(file_bytes)).convert("RGBA")
    if max(image.size) > max_dim:
        image.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

    data = np.array(image)
    return Picture(
        name=name,
        path="",
        image=image,
        data=data,
        data_bytes=data.tobytes(),
        state="plaintext"
    )


def main():
    st.set_page_config(layout="wide")
    st.title("🔒 AES Image Encryption GUI")

    with st.sidebar:
        uploaded_files = st.file_uploader("Upload images", type=["png", "jpg", "jpeg"], accept_multiple_files=True)

    if 'pictures' not in st.session_state:
        st.session_state.pictures = {}
    if 'encrypted' not in st.session_state:
        st.session_state.encrypted = {}
    if 'decrypted' not in st.session_state:
        st.session_state.decrypted = {}

    modes = {
        "ECB": AES.MODE_ECB,
        "CBC": AES.MODE_CBC,
        "CFB": AES.MODE_CFB,
        "OFB": AES.MODE_OFB,
        "CTR": AES.MODE_CTR,
    }

    if uploaded_files:
        for file in uploaded_files:
            name = file.name
            if name not in st.session_state.pictures:
                file_bytes = file.read()
                st.session_state.pictures[name] = process_uploaded_image(file_bytes, name)

        for name, pic in st.session_state.pictures.items():
            col1, col2, col3 = st.columns([0.5, 0.3, 0.5])

            with col1:
                st.image(pic.image, caption=f"{name} - {pic.state}", width=250)

            with col2:
                mode_key = f"mode_{name}"
                selected_mode = st.selectbox("Mode", options=list(modes.keys()), key=mode_key)
                if st.button("Encrypt", key=f"encrypt_{name}"):
                    mode = modes[selected_mode]
                    key = get_random_bytes(16)
                    iv = get_random_bytes(16) if mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB] else \
                        get_random_bytes(8) if mode == AES.MODE_CTR else None

                    encrypted_img, encrypted_array = AES_interface.aes_encrypt(
                        pic.data, pic.data_bytes, key, iv_or_nonce=iv, aes_mode=mode
                    )

                    st.session_state.encrypted[name] = EncryptedPicture(
                        name=f"{name}_enc",
                        path="",
                        image=encrypted_img,
                        data=encrypted_array,
                        data_bytes=encrypted_array.tobytes(),
                        state="encrypted",
                        iv=iv,
                        key=key
                    )

            with col3:
                if name in st.session_state.encrypted:
                    st.image(st.session_state.encrypted[name].image, caption="Encrypted", width=250)


if __name__ == "__main__":
    # AES.MODE_CBC ou AES.MODE_ECB, AES.MODE_CTR, etc.
    main()
