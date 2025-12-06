import argparse
import sys
from .lsb import encode, decode, capacity_info
from PIL import Image


def main():
    parser = argparse.ArgumentParser(
        description="LSB Steganography Tool – Hide and extract messages inside images."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -------------------------
    # Encode command
    # -------------------------
    enc = sub.add_parser("encode", help="Embed a secret message into an image.")
    enc.add_argument("-i", "--input", required=True, help="Path to cover image")
    enc.add_argument("-o", "--output", required=True, help="Path for output stego image")
    enc.add_argument("-m", "--message", required=False, help="Message text")
    enc.add_argument("--message-file", required=False, help="Path to text file containing secret message")

    # -------------------------
    # Decode command
    # -------------------------
    dec = sub.add_parser("decode", help="Extract a hidden message from a stego image.")
    dec.add_argument("-i", "--input", required=True, help="Path to stego image")

    # -------------------------
    # Capacity command
    # -------------------------
    cap = sub.add_parser("capacity", help="Show max hidden-data capacity of an image.")
    cap.add_argument("-i", "--input", required=True, help="Path to an image")

    args = parser.parse_args()

    # -------------------------
    # Handler: encode
    # -------------------------
    if args.command == "encode":
        if args.message:
            message = args.message
        elif args.message_file:
            try:
                with open(args.message_file, "r", encoding="utf-8") as f:
                    message = f.read().strip()
            except Exception as e:
                print(f"Error reading message file: {e}")
                sys.exit(1)
        else:
            print("Error: Provide --message or --message-file.")
            sys.exit(1)

        try:
            encode(args.input, args.output, message)
            print(f"[+] Stego image saved to: {args.output}")
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

    # -------------------------
    # Handler: decode
    # -------------------------
    elif args.command == "decode":
        try:
            msg = decode(args.input)
            print("\n[+] Hidden Message Found:\n")
            print(msg)
            print()
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

    # -------------------------
    # Handler: capacity
    # -------------------------
    elif args.command == "capacity":
        try:
            img = Image.open(args.input)
            bits, max_bytes = capacity_info(img)
            print(f"[+] Image Capacity:")
            print(f"    Available Bits : {bits}")
            print(f"    Max Bytes      : {max_bytes}")
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
