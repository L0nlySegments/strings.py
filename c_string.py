def read_c_string(file, offset, length):
    file.seek(offset)

    in_str = False
    c_str = ""
    for _ in range(0, length):
        curr_byte = int.from_bytes(file.read(1), byteorder='little')

        if is_printable(curr_byte) and not in_str:
            in_str = True

        if in_str:
            if not is_printable(curr_byte):
                break

            c_str += chr(curr_byte)

    return c_str


def decode(c_str):
    return ''.join([chr(int(c_str[i:i+2], 16)) for i in range(len(c_str) - 2, -1, -2)])

def is_printable(byte):
    return (byte > 31 and byte < 127) or byte == 0x0a or byte == 0x09






