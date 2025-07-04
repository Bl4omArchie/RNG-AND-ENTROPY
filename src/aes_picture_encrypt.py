from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import os


class AES_interface():
    @staticmethod
    def pad_image(data):
        pad_len = 16 - (len(data) % 16)
        return data + b'\0' * pad_len

    @staticmethod
    def aes_encrypt(data, data_bytes, key, enc_file_path, aes_mode=AES.MODE_ECB, iv_or_nonce=None):
        if aes_mode in [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            cipher = AES.new(key, aes_mode, iv_or_nonce) if iv_or_nonce else AES.new(key, aes_mode)
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
        encrypted_image.save(enc_file_path)
        return encrypted_image

    @staticmethod
    def aes_decrypt(enc_img_array, key, dec_file_path, aes_mode=AES.MODE_ECB, iv_or_nonce=None):
        data_bytes = enc_img_array.tobytes()

        if aes_mode in [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            cipher = AES.new(key, aes_mode, iv_or_nonce) if iv_or_nonce else AES.new(key, aes_mode)
        elif aes_mode == AES.MODE_CTR:
            cipher = AES.new(key, aes_mode, nonce=iv_or_nonce)

        decrypted_data = cipher.decrypt(data_bytes)
        decrypted_data = decrypted_data[:enc_img_array.size]
        decrypted_array = np.frombuffer(decrypted_data, dtype=np.uint8)
        decrypted_array = decrypted_array.reshape(enc_img_array.shape)

        decrypted_image = Image.fromarray(decrypted_array)
        decrypted_image.save(dec_file_path)
        return decrypted_image


class Picture_Encryption(AES_interface):
    def __init__(self, format_file="RGBA", storage_folder="pic/", aes_mode=AES.MODE_ECB):
        self.format_file = format_file
        self.storage_folder = storage_folder
        self.aes_mode = aes_mode
        self.set_images = {}
        self.enc_map = {}

        self.enc_folder = os.path.join(storage_folder, "encrypted")
        self.dec_folder = os.path.join(storage_folder, "decrypted")

        os.makedirs(self.enc_folder, exist_ok=True)
        os.makedirs(self.dec_folder, exist_ok=True)

    def upload_image(self, picture_path):
        if os.path.isfile(picture_path):
            image = Image.open(picture_path).convert(self.format_file)
            data = np.array(image)
            data_bytes = data.tobytes()
            self.set_images[picture_path] = [image, data, data_bytes, "plaintext"]
        else:
            return -1

    def upload_folder(self, folder):
        if os.path.exists(folder):
            for filename in os.listdir(folder):
                full_path = os.path.join(folder, filename)
                self.upload_image(full_path)

    def encrypt_picture(self):
        if not self.set_images:
            raise ValueError("Please upload pictures")

        for i, (filename, data_image) in enumerate(list(self.set_images.items())):
            key = get_random_bytes(16)

            if self.aes_mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
                iv = get_random_bytes(16)
                iv_or_nonce = iv
            elif self.aes_mode == AES.MODE_CTR:
                iv_or_nonce = get_random_bytes(8)
            else:
                iv_or_nonce = None

            enc_name = f"encrypted_{i}.png"
            enc_path = os.path.join(self.enc_folder, enc_name)

            encrypted_img = self.aes_encrypt(
                data_image[1], data_image[2], key, enc_path, self.aes_mode, iv_or_nonce
            )

            self.set_images[enc_path] = [encrypted_img, np.array(encrypted_img), np.array(encrypted_img).tobytes(), "enc"]
            self.enc_map[enc_path] = (filename, key, iv_or_nonce)

    def decrypt_folder(self):
        for i, (enc_filename, data_image) in enumerate({k: v for k, v in self.set_images.items() if v[3] == "enc"}.items()):
            original_filename, key, iv_or_nonce = self.enc_map.get(enc_filename, (None, None, None))
            if key is None:
                continue

            dec_name = f"decrypted_{i}.png"
            dec_path = os.path.join(self.dec_folder, dec_name)

            decrypted_img = self.aes_decrypt(
                data_image[1], key, dec_path, self.aes_mode, iv_or_nonce
            )

            self.set_images[dec_path] = [decrypted_img, np.array(decrypted_img), np.array(decrypted_img).tobytes(), "dec"]

    def get_state(self):
        print("========================")
        for key, val in self.set_images.items():
            print(f"{key} : {val[0].size} - {val[-1]}")


if __name__ == "__main__":
    # AES.MODE_CBC ou AES.MODE_ECB, AES.MODE_CTR, etc.
    mode = AES.MODE_ECB

    obj = Picture_Encryption(aes_mode=mode)
    obj.upload_folder("pic/originals/")
    obj.get_state()

    obj.encrypt_picture()
    obj.decrypt_folder()
    obj.get_state()
