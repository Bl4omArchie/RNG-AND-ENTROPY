from scipy.stats import entropy as shannon_entropy
from dataclasses import dataclass
from PIL import Image

import numpy as np
import os


@dataclass
class Picture:
    name: str
    path: str
    image: Image.Image
    entropy: float
    data: np.ndarray
    data_bytes: bytes
    state: str

@dataclass
class EncryptedPicture(Picture):
    iv: bytes
    key: bytes


def compute_image_entropy(image: Image.Image) -> float:
    grayscale = image.convert('L')
    histogram = grayscale.histogram()
    total_pixels = sum(histogram)
    probabilities = [count / total_pixels for count in histogram if count > 0]
    return shannon_entropy(probabilities, base=2)


def get_encrypted_picture(name: str, path: str, image: Image.Image, key: bytes, iv: bytes) -> EncryptedPicture:
    if os.path.isfile(path):
        entropy = compute_image_entropy(image)
        data = np.array(image)
        data_bytes = data.tobytes()
        
        return EncryptedPicture(
            name=name,
            path=path,
            image=image,
            entropy=entropy,
            data=data,
            data_bytes=data_bytes,
            state="encrypted",
            iv=iv,
            key=key
        )
    return -1


def get_image(name: str, path: str, image: Image.Image, status: str):
    entropy = compute_image_entropy(image)
    data = np.array(image)
    data_bytes = data.tobytes()
    
    return Picture(name, path, image, entropy, data, data_bytes, status)


def get_image_from_path(picture_path: str, status: str, format_file="RGBA") -> Picture:
    if os.path.isfile(picture_path):
        image = Image.open(picture_path).convert(format_file)
        entropy = compute_image_entropy(image)
        data = np.array(image)
        data_bytes = data.tobytes()
        
        return Picture(os.path.splitext(os.path.basename(picture_path))[0], picture_path, image, entropy, data, data_bytes, status)
    
    else:
        return -1
