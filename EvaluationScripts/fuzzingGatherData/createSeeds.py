import struct
import base64

def cyclic(length, n=4):
    pattern = b''
    sequence = b''
    count = 0

    while count < length:
        if len(sequence) == n:
            pattern += sequence
            sequence = b''
        sequence += struct.pack('<h', count)
        count += 1
    
    return pattern

def seed(ioctl, inputSize, outputSize, empty):
    data = struct.pack('<Ihh', ioctl, inputSize, 0x1000)
    total_size = inputSize + outputSize
    data += b'\x00' * total_size if empty else cyclic(total_size)[:total_size]
    return base64.b64encode(data).decode()

def create_ioctl_seeds_for(ioctl_comp):
    
    ioctl_set = set()
    for ioctl in ioctl_comp:
        if "=" in ioctl['op']:
            ioctl_set.add(ioctl['val'])
        # should get us into both branches
        if "<" in ioctl['op']:
            ioctl_set.add(ioctl['val'] - 0x4)
            ioctl_set.add(ioctl['val'])
        if ">" in ioctl['op']:
            ioctl_set.add(ioctl['val'] + 0x4)
            ioctl_set.add(ioctl['val'])
    

    seed_obj = []
    for ioctl in ioctl_set:
        seeds = [
            #seed(ioctl, inputSize=8, outputSize=8, empty=True),
            seed(ioctl, inputSize=16, outputSize=16, empty=True),
            #seed(ioctl, inputSize=0x80, outputSize=0x80, empty=True),
            seed(ioctl, inputSize=0x80, outputSize=0x80, empty=False),
            seed(ioctl, inputSize=0x1000, outputSize=0x1000, empty=True),
            #seed(ioctl, inputSize=0x1000, outputSize=0x1000, empty=False),
        ]
        seed_obj.append(seeds)
    return seed_obj


if __name__ == '__main__':
    ioctl_comp = [
        {
            'op': '==',
            'val': 0x222003
        },
        {
            'op': '==',
            'val': 0x222007
        }
    ]
    seed_obj = create_ioctl_seeds_for(ioctl_comp)
    for s in seed_obj:
        print(f"'{s}',")

    print(f"{seed(0x000000, 16, 16, True)}")
    print(f"{seed(0x000000, 0x80, 0x80, False)}")
    print(f"{seed(0x000000, 0x1000, 0x1000, True)}")
    
