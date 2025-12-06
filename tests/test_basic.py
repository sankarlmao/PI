# tests/test_basic.py
from steg.lsb import encode, decode
from PIL import Image
import numpy as np
import os

def test_roundtrip(tmp_path):
    # Create small cover image
    arr = (np.random.rand(20, 20, 3) * 255).astype('uint8')
    img = Image.fromarray(arr)
    cover = tmp_path / "cover.png"
    img.save(cover)

    out = tmp_path / "stego.png"
    message = "this is a test message"
    encode(str(cover), str(out), message)
    decoded = decode(str(out))
    assert decoded == message
