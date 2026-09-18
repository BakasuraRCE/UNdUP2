import argparse
from pathlib import Path

import lief
from lief.PE import ResourceNode


def padded_4_bytes_length(num: int) -> int:
    """https://stackoverflow.com/questions/11642210/computing-padding-required-for-n-byte-alignment"""
    return (4 - (num % 4)) % 4


def padded_16_bytes_length(num: int) -> int:
    """https://stackoverflow.com/questions/11642210/computing-padding-required-for-n-byte-alignment"""
    return (16 - (num % 16)) % 16


def align_16(body: bytes) -> bytes:
    if _ := padded_16_bytes_length(len(body)):
        body += b'\x00' * _

    return body


def decrypt_bytes(data: bytes, key: int = 0xDEADBEEF) -> bytes:
    byte_array = bytearray(data)
    ebx = key
    ecx = len(byte_array)
    esi = 0

    while ecx > 0:
        dl: int = byte_array[esi]
        al: int = dl ^ (ebx & 0xFF)

        byte_array[esi] = al

        # RTR
        ebx = (ebx >> 1) | ((ebx & 1) << 31)

        ebx ^= dl
        ebx = (ebx + ecx) & 0xFFFFFFFF

        ecx -= 1
        esi += 1

    return bytes(byte_array)


def resource_data_bytes(node: ResourceNode) -> bytes | None:
    if node.is_data:
        content = node.content
        return content.tobytes() if hasattr(content, 'tobytes') else bytes(content)

    for child in node.childs:
        content = resource_data_bytes(child)
        if content is not None:
            return content

    return None


def main() -> None:
    desp = 'UNdUP2: dUP2 Unpacker / Decompiler | Bakasura - 2024'
    parser = argparse.ArgumentParser(description=desp)
    parser.add_argument('file_path', type=str, help='dup2 exe')
    args = parser.parse_args()

    print(desp)

    exe_path = Path(args.file_path)

    binary = lief.parse(args.file_path)

    if binary is None:
        raise Exception(f'{exe_path.name} is not a valid PE file')

    if not binary.has_resources:
        raise Exception(f'{exe_path.name} not have resources')

    res_manager: lief.PE.ResourcesManager = binary.resources_manager
    rcdata = res_manager.get_node_type(lief.PE.ResourcesManager.TYPE.RCDATA)

    if rcdata is None:
        raise Exception(f'{exe_path.name} has no RCDATA resources')

    dll_bytes = resource_data_bytes(rcdata)
    if dll_bytes is None:
        raise Exception('Could not find DLL bytes in RCDATA resources')

    dll_bytes = decrypt_bytes(dll_bytes)

    exe_path.parent.joinpath(f'{exe_path.stem}.dumped.dll').write_bytes(dll_bytes)

    make_dup2_file(dll_bytes, exe_path.parent.joinpath(f'{exe_path.stem}.dUP2'))

    print('Unpacked!')


def make_dup2_file(dll_bytes: bytes, dup2_project_path: Path) -> None:
    binary = lief.parse(dll_bytes)

    if binary is None:
        raise Exception('Could not parse dumped DLL')

    if not binary.has_resources:
        raise Exception('Dumped dll not have resources')

    res_manager: lief.PE.ResourcesManager = binary.resources_manager
    rcdata = res_manager.get_node_type(lief.PE.ResourcesManager.TYPE.RCDATA)

    if rcdata is None:
        raise Exception('Dumped DLL has no RCDATA resources')

    dup2_content = bytearray()
    modules = 0
    modules_search_and_replace = 0

    for child in rcdata.childs:
        # plugins have name that is the HASH of content, we can skip safe
        if child.has_name:
            continue

        content = resource_data_bytes(child)
        if content is None:
            continue

        # count modules
        modules += 1

        # count modules of type "search and replace"
        if content and content[0] == 4:
            modules_search_and_replace += 1

        # put len and content
        dup2_content.extend(len(content).to_bytes(4, byteorder='little'))
        dup2_content.extend(content)

    # align
    dup2_content = bytearray(align_16(bytes(dup2_content)))

    # len of content + 16 bytes of header
    comment_address = len(dup2_content) + 0x10

    # include empty comments (48 len + 48 empty bytes per module)
    empty_comment_block = b'\x30' + b'\x00' * (3 + 0x30)
    dup2_content.extend(empty_comment_block * modules_search_and_replace)

    dup2_content = (
        modules.to_bytes(4, byteorder='little')
        + comment_address.to_bytes(4, byteorder='little')
        + (b'\x00' * 8)
        + dup2_content
    )

    # align
    dup2_content = align_16(dup2_content)

    dup2_project_path.write_bytes(dup2_content)


if __name__ == '__main__':
    main()
