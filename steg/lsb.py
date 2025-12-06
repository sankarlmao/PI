# steg/lsb.py
from PIL import Image
import numpy as np
import argparse
import os
import math
import sys
from typing import Tuple

MAGIC = b"LSB1"   # signature to identify our stego images

def _to_bits(data: bytes) -> list:
    """Convert bytes to a list of bits (0/1)."""
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits

def _from_bits(bits: list) -> bytes:
    """Convert list of bits (length multiple of 8) back to bytes."""
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)

def capacity_info(image: Image.Image) -> Tuple[int,int]:
    """Return (available_bits, max_bytes) for RGB images."""
    arr = np.array(image)
    if arr.ndim == 2:  # grayscale
        channels = 1
    else:
        channels = arr.shape[2]
    pixels = arr.shape[0] * arr.shape[1]
    available_bits = pixels * channels  # using 1 bit per channel
    return available_bits, available_bits // 8

def encode(cover_path: str, out_path: str, message: str) -> None:
    """Encode message into cover image and save to out_path."""
    if not os.path.exists(cover_path):
        raise FileNotFoundError(cover_path)
    img = Image.open(cover_path)
    img = img.convert("RGBA") if img.mode == "RGBA" else img.convert("RGB")
    arr = np.array(img)
    h, w = arr.shape[:2]
    channels = arr.shape[2]
    available_bits = h * w * channels

    # Prepare payload: MAGIC + 4-byte length + message bytes
    message_bytes = message.encode("utf-8")
    length = len(message_bytes)
    if length > (2**32 - 1):
        raise ValueError("Message too long.")
    header = MAGIC + length.to_bytes(4, byteorder="big")
    payload = header + message_bytes
    payload_bits = _to_bits(payload)

    if len(payload_bits) > available_bits:
        raise ValueError(f"Message too large to fit in image. Capacity: {available_bits // 8} bytes, required: {len(payload_bits) // 8} bytes")

    # Flatten pixel data in row-major and channel order
    flat = arr.flatten()
    # Replace LSBs of the first N channels with payload bits
    for i, bit in enumerate(payload_bits):
        flat[i] = (flat[i] & ~1) | bit

    # Keep remaining pixels unchanged
    new_arr = flat.reshape(arr.shape)
    stego_img = Image.fromarray(new_arr.astype('uint8'), mode=img.mode)
    stego_img.save(out_path)
    print(f"Saved stego image to: {out_path}")

def decode(stego_path: str) -> str:
    """Decode message from stego image and return it as string."""
    if not os.path.exists(stego_path):
        raise FileNotFoundError(stego_path)
    img = Image.open(stego_path)
    img = img.convert("RGBA") if img.mode == "RGBA" else img.convert("RGB")
    arr = np.array(img)
    flat = arr.flatten()
    # Read enough bits at first to get MAGIC + length (MAGIC len + 4 bytes)
    header_bits_len = (len(MAGIC) + 4) * 8
    header_bits = [int(flat[i] & 1) for i in range(header_bits_len)]
    header_bytes = _from_bits(header_bits)
    if not header_bytes.startswith(MAGIC):
        raise ValueError("MAGIC signature not found: this image probably doesn't contain a message or uses a different format.")
    length_bytes = header_bytes[len(MAGIC):len(MAGIC)+4]
    length = int.from_bytes(length_bytes, byteorder="big")
    total_bits = (len(MAGIC) + 4 + length) * 8
    # Ensure image has enough bits
    if total_bits > flat.size:
        raise ValueError("Image does not contain enough data for claimed message length.")

    bits = [int(flat[i] & 1) for i in range(total_bits)]
    payload = _from_bits(bits)
    message_bytes = payload[len(MAGIC) + 4:]
    try:
        return message_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # In case of binary payload; return raw bytes repr
        return message_bytes.decode("latin1")

def main_cli():
    parser = argparse.ArgumentParser(description="Simple LSB steganography tool.")
    sub = parser.add_subparsers(dest="cmd")

    enc = sub.add_parser("encode", help="Encode a message into an image.")
    enc.add_argument("-i", "--input", required=True, help="Cover image path")
    enc.add_argument("-o", "--output", required=True, help="Output stego image path")
    enc.add_argument("-m", "--message", required=False, help="Message string (or use --message-file)")
    enc.add_argument("--message-file", required=False, help="Path to message file (text)")

    dec = sub.add_parser("decode", help="Decode message from a stego image.")
    dec.add_argument("-i", "--input", required=True, help="Stego image path")

    cap = sub.add_parser("capacity", help="Show capacity info of an image.")
    cap.add_argument("-i", "--input", required=True, help="Image path")

    args = parser.parse_args()
    if args.cmd == "encode":
        if args.message_file:
            with open(args.message_file, "rb") as f:
                message = f.read().decode("utf-8")
        elif args.message is not None:
            message = args.message
        else:
            print("No message provided. Use --message or --message-file.")
            sys.exit(1)
        encode(args.input, args.output, message)
    elif args.cmd == "decode":
        msg = decode(args.input)
        print("Decoded message:")
        print(msg)
    elif args.cmd == "capacity":
        img = Image.open(args.input)
        bits, max_bytes = capacity_info(img)
        print(f"Available bits: {bits}, Max bytes (1 LSB per channel): {max_bytes}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main_cli()
