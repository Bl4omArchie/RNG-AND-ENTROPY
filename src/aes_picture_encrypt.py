from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

from src.util import *
from PIL import Image

import numpy as np
import os


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
                img = get_image_from_path(picture_path=full_path, status="plaintext", format_file=format_file)
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

            self.enc_pictures.append(get_encrypted_picture(name=enc_name, path=enc_path, image=encrypted_img, iv=iv_or_nonce, key=key))

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

            self.pictures.append(get_image(name=dec_name, path=dec_path, image=decrypted_img, status="decrypted"))


    def get_state(self) -> None:
        print("========================")
        for pic in self.pictures:
            print(f"{pic.name} : {pic.image.size} - {pic.state}")
