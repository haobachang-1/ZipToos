import sys
import os
import argparse

def is_fake_encrypted_zip(zip_path):
    """
    检测zip文件是否为伪加密。
    伪加密：仅设置加密标志但内容未加密。
    """
    import struct
    try:
        with open(zip_path, 'rb') as f:
            data = f.read()
        offset = 0
        encrypted_count = 0
        fake_encrypted_count = 0
        while offset < len(data):
            # 检查local file header
            if data[offset:offset+4] == b'PK\x03\x04':
                flag_offset = offset + 6
                flag_bits = struct.unpack('<H', data[flag_offset:flag_offset+2])[0]
                is_encrypted = flag_bits & 0x1
                name_len = struct.unpack('<H', data[offset+26:offset+28])[0]
                extra_len = struct.unpack('<H', data[offset+28:offset+30])[0]
                comp_size = struct.unpack('<I', data[offset+18:offset+22])[0]
                if is_encrypted:
                    encrypted_count += 1
                    file_data_offset = offset + 30 + name_len + extra_len
                    file_data = data[file_data_offset:file_data_offset+12]
                    # 只要内容区前12字节为可见ASCII或长度不足12字节，判为伪加密
                    if len(file_data) < 12 or all(32 <= b <= 126 or b in (9, 10, 13) for b in file_data):
                        fake_encrypted_count += 1
                    else:
                        # 保守起见，其他情况也判为伪加密
                        fake_encrypted_count += 1
                offset += 30 + name_len + extra_len + comp_size
            elif data[offset:offset+4] == b'PK\x01\x02':
                # 跳过central directory header
                name_len = struct.unpack('<H', data[offset+28:offset+30])[0]
                extra_len = struct.unpack('<H', data[offset+30:offset+32])[0]
                comment_len = struct.unpack('<H', data[offset+32:offset+34])[0]
                offset += 46 + name_len + extra_len + comment_len
            else:
                offset += 1
        # 所有加密标志文件都为伪加密则返回True
        return encrypted_count > 0 and encrypted_count == fake_encrypted_count
    except Exception as e:
        print(f"检测压缩包时出错: {e}")
        return False

def fake_encrypt_zip(zip_path, output_path):
    """
    生成伪加密zip：仅设置加密标志，不实际加密内容。
    """
    import shutil
    import struct

    shutil.copy(zip_path, output_path)

    def set_fake_encryption_flag(file_path):
        with open(file_path, 'r+b') as f:
            data = f.read()
            new_data = bytearray(data)
            offset = 0
            while offset < len(new_data):
                if new_data[offset:offset+4] == b'PK\x03\x04':
                    # 设置local file header的加密标志
                    flag_offset = offset + 6
                    flag_bits = struct.unpack('<H', new_data[flag_offset:flag_offset+2])[0]
                    flag_bits |= 0x1
                    new_data[flag_offset:flag_offset+2] = struct.pack('<H', flag_bits)
                    name_len = struct.unpack('<H', new_data[offset+26:offset+28])[0]
                    extra_len = struct.unpack('<H', new_data[offset+28:offset+30])[0]
                    comp_size = struct.unpack('<I', new_data[offset+18:offset+22])[0]
                    offset += 30 + name_len + extra_len + comp_size
                elif new_data[offset:offset+4] == b'PK\x01\x02':
                    # 设置central directory header的加密标志
                    flag_offset = offset + 8
                    flag_bits = struct.unpack('<H', new_data[flag_offset:flag_offset+2])[0]
                    flag_bits |= 0x1
                    new_data[flag_offset:flag_offset+2] = struct.pack('<H', flag_bits)
                    name_len = struct.unpack('<H', new_data[offset+28:offset+30])[0]
                    extra_len = struct.unpack('<H', new_data[offset+30:offset+32])[0]
                    comment_len = struct.unpack('<H', new_data[offset+32:offset+34])[0]
                    offset += 46 + name_len + extra_len + comment_len
                else:
                    offset += 1
            f.seek(0)
            f.write(new_data)

    set_fake_encryption_flag(output_path)
    print(f"已生成伪加密zip文件：{output_path}")

def remove_fake_encryption_flag(file_path, output_path):
    """
    去除zip文件的伪加密标志。
    """
    import shutil
    import struct
    shutil.copy(file_path, output_path)
    with open(output_path, 'r+b') as f:
        data = f.read()
        new_data = bytearray(data)
        offset = 0
        while offset < len(new_data):
            if new_data[offset:offset+4] == b'PK\x03\x04':
                # 清除local file header的加密标志
                flag_offset = offset + 6
                flag_bits = struct.unpack('<H', new_data[flag_offset:flag_offset+2])[0]
                flag_bits &= ~0x1
                new_data[flag_offset:flag_offset+2] = struct.pack('<H', flag_bits)
                name_len = struct.unpack('<H', new_data[offset+26:offset+28])[0]
                extra_len = struct.unpack('<H', new_data[offset+28:offset+30])[0]
                comp_size = struct.unpack('<I', new_data[offset+18:offset+22])[0]
                offset += 30 + name_len + extra_len + comp_size
            elif new_data[offset:offset+4] == b'PK\x01\x02':
                # 清除central directory header的加密标志
                flag_offset = offset + 8
                flag_bits = struct.unpack('<H', new_data[flag_offset:flag_offset+2])[0]
                flag_bits &= ~0x1
                new_data[flag_offset:flag_offset+2] = struct.pack('<H', flag_bits)
                name_len = struct.unpack('<H', new_data[offset+28:offset+30])[0]
                extra_len = struct.unpack('<H', new_data[offset+30:offset+32])[0]
                comment_len = struct.unpack('<H', new_data[offset+32:offset+34])[0]
                offset += 46 + name_len + extra_len + comment_len
            else:
                offset += 1
        f.seek(0)
        f.write(new_data)

if __name__ == "__main__":
    import time

    parser = argparse.ArgumentParser(description="检测、生成或去除伪加密zip压缩包")
    parser.add_argument('-f', '--file', type=str, required=True, help='zip文件路径')
    parser.add_argument('-g', '--generate', type=str, nargs='?', const='', help='生成伪加密zip，指定输出路径（可选）')
    parser.add_argument('-u', '--unfake', type=str, nargs='?', const='', help='去除伪加密，指定输出路径（可选）')
    args = parser.parse_args()

    zip_path = args.file

    if not os.path.isfile(zip_path):
        print(f"文件不存在: {zip_path}")
        sys.exit(1)

    # 默认检测伪加密
    if args.generate is None and args.unfake is None:
        if is_fake_encrypted_zip(zip_path):
            print("该压缩包被伪加密了。")
        else:
            print("该压缩包没有被伪加密。")
    elif args.generate is not None:
        # 自动生成输出路径
        if not args.generate.strip():
            base, ext = os.path.splitext(zip_path)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"{base}_{timestamp}_wjm{ext}"
        else:
            output_path = args.generate
        fake_encrypt_zip(zip_path, output_path)
    elif args.unfake is not None:
        # 自动生成输出路径
        if not args.unfake.strip():
            base, ext = os.path.splitext(zip_path)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"{base}_{timestamp}_unwjm{ext}"
        else:
            output_path = args.unfake
        remove_fake_encryption_flag(zip_path, output_path)
        print(f"已生成去除伪加密的zip文件：{output_path}")
    else:
        print("请使用 -f 指定文件，-g 生成伪加密zip，或 -u 去除伪加密。")