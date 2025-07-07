import numpy as np
from PIL import Image


def entropy(image_path):
    img = Image.open(image_path).convert('L')
    arr = np.array(img).flatten()
    hist, _ = np.histogram(arr, bins=256, range=(0, 255))
    prob = hist / hist.sum()
    prob = prob[prob > 0]
    ent = -np.sum(prob * np.log2(prob))
    n_ent = ent / 8.0

    return float(ent), float(n_ent)


if __name__ == "__main__":
    print(entropy("pic/logo.png"))
    print(entropy("pic/wallpaper.png"))
    print(entropy("pic/logo_encrypted.png_decrypted.png"))
