from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from io import BytesIO
import streamlit as st
import numpy as np

from src.camera_byte_stream import stream_camera
from src.aes_picture_encrypt import *
from src.util import *

import cv2



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
        entropy=image.entropy(),
        data=data,
        data_bytes=data.tobytes(),
        state="plaintext"
    )


def main():
    st.set_page_config(layout="wide")

    tab1, tab2 = st.tabs(["AES encryption", "Camera rng"])

    with tab1:
        st.header("🔒 AES Image Encryption GUI")

        modes = {
            "ECB": AES.MODE_ECB,
            "CBC": AES.MODE_CBC,
            "CFB": AES.MODE_CFB,
            "OFB": AES.MODE_OFB,
            "CTR": AES.MODE_CTR,
        }

        if 'pictures' not in st.session_state:
            st.session_state.pictures = {}
        if 'encrypted' not in st.session_state:
            st.session_state.encrypted = {}
        if 'decrypted' not in st.session_state:
            st.session_state.decrypted = {}

        uploaded_files = st.file_uploader("Upload images", type=["png", "jpg", "jpeg"], accept_multiple_files=True)

        if uploaded_files:
            for file in uploaded_files:
                name = file.name
                if name not in st.session_state.pictures:
                    file_bytes = file.read()
                    st.session_state.pictures[name] = process_uploaded_image(file_bytes, name)

            st.markdown("### Encryption Settings")
            selected_mode = st.selectbox("Encryption mode", list(modes.keys()), key="global_mode")
            if st.button("🔐 Encrypt All", key="encrypt_all"):
                mode = modes[selected_mode]
                for name, pic in st.session_state.pictures.items():
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
                        entropy=encrypted_img.entropy(),
                        data=encrypted_array,
                        data_bytes=encrypted_array.tobytes(),
                        state="encrypted",
                        iv=iv,
                        key=key
                    )

        if st.session_state.pictures:
            for name, pic in st.session_state.pictures.items():
                st.markdown("---")

                col1, col2 = st.columns([0.5, 0.5])

                with col1:
                    st.image(pic.image, width=250)
                    st.markdown(f"**Name**: `{pic.name}`")
                    st.markdown(f"**Entropy**: `{pic.entropy:.4f} bits/byte`")

                with col2:
                    if name in st.session_state.encrypted:
                        st.image(st.session_state.encrypted[name].image, width=250)
                        st.markdown(f"**Encrypted Name**: `{st.session_state.encrypted[name].name}`")
                        st.markdown(f"**Entropy**: `{pic.entropy:.4f} bits/byte`")


    with tab2:
        if 'camera_running' not in st.session_state:
            st.session_state.camera_running = False

        def start_camera():
            st.session_state.camera_running = True

        def stop_camera():
            st.session_state.camera_running = False

        st.title("Camera Stream with Start/Stop")

        btn_label = "Stop Camera" if st.session_state.camera_running else "Start Camera"
        if st.button(btn_label):
            if st.session_state.camera_running:
                stop_camera()
            else:
                start_camera()

        if st.session_state.camera_running:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                st.error("Error: Could not open camera.")
            else:
                frame_placeholder = st.empty()

                while st.session_state.camera_running:
                    ret, frame = cap.read()
                    if not ret:
                        st.error("Error: Failed to grab frame.")
                        break

                    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    frame_placeholder.image(frame_rgb, channels="RGB")

                    if not st.session_state.camera_running:
                        break

                cap.release()
        else:
            st.info("Camera is stopped.")


if __name__ == "__main__":
    main()
