#!/usr/bin/env python
import struct
import sys
import os
if __name__ != "__main__":
    from payload.ioctlDecoder import decodeIt
    from payload.hexdump import hexdump
else:
    from ioctlDecoder import decodeIt
    from hexdump import hexdump
import base64

def decode_output_(data):
        # Unpack the data to retrieve ioctl, input size, and output size
        ioctl, input_size = struct.unpack('<Ih', data[:6])
        output_size = len(data) - (8 + input_size)
        # print(f"IOCTL: {hex(ioctl)}, length: {len(data)} bytes and input size: {input_size} bytes and output size: {output_size} bytes.")

        # Extract input and output byte arrays
        input_bytes = data[8:8 + input_size]
        output_bytes = data[8 + input_size:]

        return ioctl, input_bytes, output_bytes


def decode(file_path):
    data = None
    with open(file_path, 'rb') as f:
        data = f.read()

    if data is None or len(data) < 6:
        print(f"File {file_path} is too short to be an IOCTL output file.")
        return {"IOCTL": None, "Device": None, "Function": None, "Access": None, "Method": None, "InputBytes": None, "OutputBytes": None, "FullBytes": None}
    
    ioctl, input_bytes, output_bytes = decode_output_(data)
    decoded_ioctl = decodeIt(ioctl)

    # Make json serializable combination for backend, base64 encoding the bytes
    if decoded_ioctl is None:
        return {
            "IOCTL": hex(ioctl),
            "Device": "Unknown",
            "Function": "Unknown",
            "Access": "Unknown",
            "Method": "Unknown",
            "InputBytes": base64.b64encode(input_bytes).decode(),
            "OutputBytes": base64.b64encode(output_bytes).decode(),
            "FullData": base64.b64encode(data).decode()
        }
    return {
        "IOCTL": hex(ioctl),
        "Device": decoded_ioctl["Device"],
        "Function": decoded_ioctl["Function"],
        "Access": decoded_ioctl["Access"].name,
        "Method": decoded_ioctl["Method"].name,
        "InputBytes": base64.b64encode(input_bytes).decode(),
        "OutputBytes": base64.b64encode(output_bytes).decode(),
        "FullData": base64.b64encode(data).decode()
    }

def print_decode(file_path):
    data = None
    with open(file_path, 'rb') as f:
        data = f.read()
    ioctl, input_bytes, output_bytes = decode_output_(data)
    decoded_ioctl = decodeIt(ioctl)
    if decoded_ioctl is None:
        print(f'Nonsensical IOCTL!')
        return
    print(f'IOCTL: {hex(ioctl)} which is:\n\tDevice: {decoded_ioctl["Device"]}\n\tFunction: {decoded_ioctl["Function"]}\n\tAccess:{decoded_ioctl["Access"].name}\n\tMethod:{decoded_ioctl["Method"].name}')
    print(f"Input Bytes ({len(input_bytes)}):")
    print(hexdump(input_bytes))
    print(f"Output Bytes ({len(output_bytes)}):")
    print(hexdump(output_bytes))

def decode_files_in_folder(folder_path, visible=True):
    if os.path.isdir(folder_path):
        payloads = []
        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if visible:
                    print(f"\nDecoding file: {file_path}")
                    print_decode(file_path)
                else:
                    payloads.append(decode(file_path))
        return payloads
    # Not a folder to scan, just decode the file
    if visible:
        print_decode(folder_path)
    else:
        return decode(folder_path)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isdir(path) or os.path.isfile(path):
            print(decode_files_in_folder(path, visible=False))
        else:
            try:
                bin_data = base64.b64decode(path)
                ioctl, input_bytes, output_bytes = decode_output_(bin_data)
                decoded_ioctl = decodeIt(ioctl)
                print(f"IOCTL: {hex(ioctl)} which is:\n\tDevice: {decoded_ioctl['Device']}\n\tFunction: {decoded_ioctl['Function']}\n\tAccess:{decoded_ioctl['Access'].name}\n\tMethod:{decoded_ioctl['Method'].name}")
                print(f"Input Bytes ({len(input_bytes)}) and Output Bytes ({len(output_bytes)})")
            except:
                print("Invalid base64 encoded string")
    else:
        print("This is a IOCTL decoder; please provide a folder path, file path or base64 encoded as an argument")