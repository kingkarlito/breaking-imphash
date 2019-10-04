"""
The MIT License (MIT)

Copyright (c) 2019 Chris Balles, SCYTHE, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

As a side note, a big thanks to Ero Carrera who wrote PEFile
https://github.com/erocarrera/pefile and parsed out much of the Windows PE file
format! It made writing / testing out modifications to PE files significantly
easier.
"""

import time
import sys
import random
import hashlib
import datetime
import pefile
import json
import os
import struct
import pefile
from pefile import Structure
import tempfile
import subprocess
import argparse

class PEFormatError(Exception):
    """Generic PE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

__IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER',
        ('H,e_magic', 'H,e_cblp', 'H,e_cp',
        'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc',
        'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum',
        'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res',
        'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
        'I,e_lfanew'))

__IMAGE_NT_HEADERS_format__ = ('IMAGE_NT_HEADERS', ('I,Signature',))

__IMAGE_FILE_HEADER_format__ = ('IMAGE_FILE_HEADER',
        ('H,Machine', 'H,NumberOfSections',
        'I,TimeDateStamp', 'I,PointerToSymbolTable',
        'I,NumberOfSymbols', 'H,SizeOfOptionalHeader',
        'H,Characteristics'))

__IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER',
    ('H,Magic', 'B,MajorLinkerVersion',
    'B,MinorLinkerVersion', 'I,SizeOfCode',
    'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
    'I,AddressOfEntryPoint', 'I,BaseOfCode', 'I,BaseOfData',
    'I,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
    'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
    'H,MajorImageVersion', 'H,MinorImageVersion',
    'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
    'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
    'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
    'I,SizeOfStackReserve', 'I,SizeOfStackCommit',
    'I,SizeOfHeapReserve', 'I,SizeOfHeapCommit',
    'I,LoaderFlags', 'I,NumberOfRvaAndSizes' ))


__IMAGE_OPTIONAL_HEADER64_format__ = ('IMAGE_OPTIONAL_HEADER64',
    ('H,Magic', 'B,MajorLinkerVersion',
    'B,MinorLinkerVersion', 'I,SizeOfCode',
    'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
    'I,AddressOfEntryPoint', 'I,BaseOfCode',
    'Q,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
    'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
    'H,MajorImageVersion', 'H,MinorImageVersion',
    'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
    'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
    'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
    'Q,SizeOfStackReserve', 'Q,SizeOfStackCommit',
    'Q,SizeOfHeapReserve', 'Q,SizeOfHeapCommit',
    'I,LoaderFlags', 'I,NumberOfRvaAndSizes' ))

__IMAGE_DATA_DIRECTORY_format__ = ('IMAGE_DATA_DIRECTORY',
    ('I,VirtualAddress', 'I,Size'))

__IMAGE_IMPORT_DESCRIPTOR_format__ =  ('IMAGE_IMPORT_DESCRIPTOR',
    ('I,OriginalFirstThunk,Characteristics',
    'I,TimeDateStamp', 'I,ForwarderChain', 'I,Name', 'I,FirstThunk'))

__IMAGE_THUNK_DATA_format__ = ('IMAGE_THUNK_DATA',
    ('I,ForwarderString,Function,Ordinal,AddressOfData',))

__IMAGE_THUNK_DATA64_format__ = ('IMAGE_THUNK_DATA',
    ('Q,ForwarderString,Function,Ordinal,AddressOfData',))

__IMAGE_SECTION_HEADER_format__ = ('IMAGE_SECTION_HEADER',
    ('8s,Name', 'I,Misc,Misc_PhysicalAddress,Misc_VirtualSize',
    'I,VirtualAddress', 'I,SizeOfRawData', 'I,PointerToRawData',
    'I,PointerToRelocations', 'I,PointerToLinenumbers',
    'H,NumberOfRelocations', 'H,NumberOfLinenumbers',
    'I,Characteristics'))

__IMAGE_BASE_RELOCATION_format__ = ('IMAGE_BASE_RELOCATION',
    ('I,VirtualAddress', 'I,SizeOfBlock'))

__IMAGE_BASE_RELOCATION_ENTRY_format__ = ('IMAGE_BASE_RELOCATION_ENTRY',
    ('H,Data',) )

__IMAGE_DEBUG_DIRECTORY_format__ = ('IMAGE_DEBUG_DIRECTORY',
    ('I,Characteristics', 'I,TimeDateStamp', 'H,MajorVersion',
    'H,MinorVersion', 'I,Type', 'I,SizeOfData', 'I,AddressOfRawData',
    'I,PointerToRawData'))

directory_entry_types = [
    ('IMAGE_DIRECTORY_ENTRY_EXPORT',        0),
    ('IMAGE_DIRECTORY_ENTRY_IMPORT',        1),
    ('IMAGE_DIRECTORY_ENTRY_RESOURCE',      2),
    ('IMAGE_DIRECTORY_ENTRY_EXCEPTION',     3),
    ('IMAGE_DIRECTORY_ENTRY_SECURITY',      4),
    ('IMAGE_DIRECTORY_ENTRY_BASERELOC',     5),
    ('IMAGE_DIRECTORY_ENTRY_DEBUG',         6),

    # Architecture on non-x86 platforms
    ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT',     7),

    ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR',     8),
    ('IMAGE_DIRECTORY_ENTRY_TLS',           9),
    ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',   10),
    ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',  11),
    ('IMAGE_DIRECTORY_ENTRY_IAT',           12),
    ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',  13),
    ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',14),
    ('IMAGE_DIRECTORY_ENTRY_RESERVED',      15) ]

DIRECTORY_ENTRY = dict(
    [(e[1], e[0]) for e in directory_entry_types]+directory_entry_types)

FILE_ALIGNMENT_HARDCODED_VALUE = 0x200

IMAGE_DOS_SIGNATURE             = 0x5A4D
IMAGE_DOSZM_SIGNATURE           = 0x4D5A
IMAGE_NE_SIGNATURE              = 0x454E
IMAGE_LE_SIGNATURE              = 0x454C
IMAGE_LX_SIGNATURE              = 0x584C
IMAGE_TE_SIGNATURE              = 0x5A56 # Terse Executables have a 'VZ' signature

IMAGE_NT_SIGNATURE              = 0x00004550
IMAGE_NUMBEROF_DIRECTORY_ENTRIES= 16
IMAGE_ORDINAL_FLAG              = 0x80000000
IMAGE_ORDINAL_FLAG64            = 0x8000000000000000
OPTIONAL_HEADER_MAGIC_PE        = 0x10b
OPTIONAL_HEADER_MAGIC_PE_PLUS   = 0x20b

def get_data_slice(data, start, size):
    return data[start: start + size]

def get_data_slice(data, start, size):
    return data[start: start + size]

def get_structures_from_data(data):
    header_data = data[0:64]

    structure_header = Structure(__IMAGE_DOS_HEADER_format__, file_offset=0)

    structure_header.__unpack__(header_data)
    #print (structure_header)

    if structure_header.e_magic == IMAGE_DOSZM_SIGNATURE:
        raise PEFormatError('Probably a ZM Executable (not a PE file).')
    if not structure_header or structure_header.e_magic != IMAGE_DOS_SIGNATURE:
        raise PEFormatError('DOS Header magic not found.')

    if structure_header.e_lfanew > len(data):
        raise PEFormatError('Invalid e_lfanew value, probably not a PE file')

    nt_headers_offset = structure_header.e_lfanew
    nt_headers_structure = Structure(__IMAGE_NT_HEADERS_format__, file_offset=nt_headers_offset)
    nt_headers_structure.__unpack__(data[nt_headers_offset:nt_headers_offset+8])

    file_header_structure = Structure(__IMAGE_FILE_HEADER_format__, file_offset=nt_headers_offset+4)
    file_header_structure.__unpack__(data[nt_headers_offset+4:nt_headers_offset+4+32])

    if (0xFFFF & nt_headers_structure.Signature) == IMAGE_NE_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a NE file')
    if (0xFFFF & nt_headers_structure.Signature) == IMAGE_LE_SIGNATURE:
        raise PEFormatError('Invalid NT Headers signature. Probably a LE file')
    if (0xFFFF & nt_headers_structure.Signature) == IMAGE_LX_SIGNATURE:
        raise PEFormatError('Invalid NT Headers signature. Probably a LX file')
    if (0xFFFF & nt_headers_structure.Signature) == IMAGE_TE_SIGNATURE:
        raise PEFormatError('Invalid NT Headers signature. Probably a TE file')
    if nt_headers_structure.Signature != IMAGE_NT_SIGNATURE:
        raise PEFormatError('Invalid NT Headers signature.')

    optional_header_offset = nt_headers_offset+4+file_header_structure.sizeof()
    sections_offset = optional_header_offset + file_header_structure.SizeOfOptionalHeader

    optional_header_structure = Structure(__IMAGE_OPTIONAL_HEADER_format__, file_offset=optional_header_offset)
    optional_header_structure.__unpack__(data[optional_header_offset:optional_header_offset+256])

    # According to solardesigner's findings for his
    # Tiny PE project, the optional header does not
    # need fields beyond "Subsystem" in order to be
    # loadable by the Windows loader (given that zeros
    # are acceptable values and the header is loaded
    # in a zeroed memory page)
    # If trying to parse a full Optional Header fails
    # we try to parse it again with some 0 padding
    #
    MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69
    if ( optional_header_structure is None and
        len(data[optional_header_offset:optional_header_offset+0x200])
            >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE ):

        # Add enough zeros to make up for the unused fields
        #
        padding_length = 128

        # Create padding
        #
        padded_data = data[optional_header_offset:optional_header_offset+0x200] + (
            b'\0' * padding_length)

        optional_header_structure = structure(__IMAGE_OPTIONAL_HEADER_format__, file_offset=optional_header_offset)
        optional_header_structure.__unpack__(padded_data)

    pe_type = None
    # Check the Magic in the OPTIONAL_HEADER and set the PE file
    # type accordingly
    #
    if optional_header_structure is not None:

        if optional_header_structure.Magic == OPTIONAL_HEADER_MAGIC_PE:

            pe_type = OPTIONAL_HEADER_MAGIC_PE

        elif optional_header_structure.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS:

            pe_type = OPTIONAL_HEADER_MAGIC_PE_PLUS

            optional_header_structure = Structure(__IMAGE_OPTIONAL_HEADER64_format__, file_offset=optional_header_offset)
            optional_header_structure.__unpack__(data[optional_header_offset:optional_header_offset+0x200])

            # Again, as explained above, we try to parse
            # a reduced form of the Optional Header which
            # is still valid despite not including all
            # structure members
            #
            MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69+4

            if ( optional_header_structure is None and
                len(data[optional_header_offset:optional_header_offset+0x200])
                    >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE ):

                padding_length = 128
                padded_data = data[optional_header_offset:optional_header_offset+0x200] + (
                    b'\0' * padding_length)

                optional_header_structure = structure(__IMAGE_OPTIONAL_HEADER64_format__, file_offset=optional_header_offset)
                optional_header_structure.__unpack__(padded_data)


    # OC Patch:
    # Die gracefully if there is no OPTIONAL_HEADER field
    if optional_header_structure is None:
        raise PEFormatError("No Optional Header found, invalid PE32 or PE32+ file.")


    optional_header_structure.DATA_DIRECTORY = []
    #offset = (optional_header_offset + file_header_structure.SizeOfOptionalHeader)
    offset = (optional_header_offset + optional_header_structure.sizeof())


    nt_headers_structure.FILE_HEADER = file_header_structure
    nt_headers_structure.OPTIONAL_HEADER = optional_header_structure

    MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES = 0x100
    for i in range(int(0x7fffffff & optional_header_structure.NumberOfRvaAndSizes)):

        if len(data) - offset == 0:
            break

        if len(data) - offset < 8:
            data_new = data[offset:] + b'\0'*8
        else:
            data_new = data[offset:offset+MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES]

        dir_entry_structure = Structure(__IMAGE_DATA_DIRECTORY_format__, file_offset=offset)
        dir_entry_structure.__unpack__(data_new)

        if dir_entry_structure is None:
            break

        # Would fail if missing an entry
        try:
            dir_entry_structure.name = DIRECTORY_ENTRY[i]
        except (KeyError, AttributeError):
            break

        offset += dir_entry_structure.sizeof()

        optional_header_structure.DATA_DIRECTORY.append(dir_entry_structure)

        # If the offset goes outside the optional header,
        # the loop is broken, regardless of how many directories
        # NumberOfRvaAndSizes says there are
        #
        # We assume a normally sized optional header, hence that we do
        # a sizeof() instead of reading SizeOfOptionalHeader.
        # Then we add a default number of directories times their size,
        # if we go beyond that, we assume the number of directories
        # is wrong and stop processing
        if offset >= (optional_header_offset +
            optional_header_structure.sizeof() + 8*16) :

            break

    #print("optional headers")
    #print(optional_header_structure)
    return structure_header, nt_headers_structure, file_header_structure, optional_header_structure, pe_type

def get_pointer_from_rva(data, rva, structure_header, nt_headers_structure, file_header_structure, optional_header_structure):
    first_section_offset = get_first_section_header(structure_header, nt_headers_structure, file_header_structure)

    section_header = get_section_header(data, file_header_structure.NumberOfSections, first_section_offset, rva)

    if section_header is None:
        return -1

    delta = section_header.PointerToRawData

    offset = rva - section_header.VirtualAddress + section_header.PointerToRawData
    return offset



def get_first_section_header(structure_header, nt_headers_structure, file_header_structure):
    nt_headers_offset = structure_header.e_lfanew
    optional_header_offset = nt_headers_offset+4+file_header_structure.sizeof()
    first_section = optional_header_offset + file_header_structure.SizeOfOptionalHeader
    return first_section

def get_section_header(data, num_headers, first_section_offset, rva):
    current_offset = first_section_offset
    section_header = Structure(__IMAGE_SECTION_HEADER_format__, file_offset = None)

    i = 0
    for i in range(num_headers):
        section_header.__unpack__(data[current_offset:])
        #print(section_header)

        if rva >= section_header.VirtualAddress and rva < section_header.VirtualAddress + section_header.Misc_VirtualSize:
            return section_header

        current_offset += section_header.sizeof()
    return None

def count_zeroes(data):
    try:
        # newbytes' count() takes a str in Python 2
        count = data.count('\0')
    except TypeError:
        # bytes' count() takes an int in Python 3
        count = data.count(0)
    return count

def get_string_from_data(data, offset):
    """Get an ASCII string from data."""
    s = data[offset:]
    end = s.find(b'\0')
    if end >= 0:
        s = s[:end]
    return s

def modify_imphash(data):
    structure_header, nt_headers_structure, file_header_structure, optional_header_structure, pe_type = get_structures_from_data(data)
    intersection_of_lists = []
    import_address_structure = []
    for structure in optional_header_structure.DATA_DIRECTORY:
        if structure.name == 'IMAGE_DIRECTORY_ENTRY_IMPORT':
            current_rva = get_pointer_from_rva(data, structure.VirtualAddress, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)
            count = 0
            while True:
                current_data = get_data_slice(data, current_rva, Structure(
                        __IMAGE_IMPORT_DESCRIPTOR_format__).sizeof())

                import_descriptor_structure = Structure(__IMAGE_IMPORT_DESCRIPTOR_format__, file_offset=current_rva)
                import_descriptor_structure.__unpack__(current_data)

                if import_descriptor_structure == None or import_descriptor_structure.all_zeroes():
                    break
                max_len = max(structure.VirtualAddress-import_descriptor_structure.OriginalFirstThunk, structure.VirtualAddress-import_descriptor_structure.FirstThunk)
                name_rva = get_pointer_from_rva(data, import_descriptor_structure.Name, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)

                name = get_string_from_data(data, name_rva)
                print("Name: %s" % name)

                data = shuffle_imports(data, pe_type, import_descriptor_structure.OriginalFirstThunk, import_descriptor_structure.FirstThunk, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)
                current_rva += import_descriptor_structure.sizeof()
                count += 1
            break

    return data

def shuffle_imports(data, pe_type, thunk, first_thunk, structure_header, nt_headers_structure, file_header_structure, optional_header_structure):
    ordinal_flag = IMAGE_ORDINAL_FLAG
    format = __IMAGE_THUNK_DATA_format__

    import_offset = get_pointer_from_rva(data, thunk, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)
    ft_offset = get_pointer_from_rva(data, first_thunk, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)
    current_offset = import_offset
    byte_replacement_size = 4
    byte_replacement_format = 'I'
    if pe_type == OPTIONAL_HEADER_MAGIC_PE_PLUS:
        ordinal_flag = IMAGE_ORDINAL_FLAG64
        format = __IMAGE_THUNK_DATA64_format__
        byte_replacement_size = 8
        byte_replacement_format = 'Q'
        raise ValueError("Only able to modify 32 bit files with this iteration of the code.")
        return data

    number_of_imports = 0
    thunks = []
    first_thunk_data = []
    first_thunk_address = first_thunk
    names = []
    hint_words = []
    rva = thunk
    thunk_data_structure = Structure(format, file_offset=current_offset)
    name_thunks = []
    while True:
        data_current = data[current_offset:current_offset + thunk_data_structure.sizeof()]
        thunk_data_structure = Structure(format, file_offset=current_offset)
        thunk_data_structure.__unpack__(data_current)

        if count_zeroes(data_current) == thunk_data_structure.sizeof():
            break

        if thunk_data_structure.AddressOfData & ordinal_flag:
            imp_ord = thunk_data_structure.AddressOfData & 0xffff
            raise ValueError("Import By Ordinal Not Supported")
        else:
            first_thunk_data.append(first_thunk_address)
            hint_rva= get_pointer_from_rva(data, thunk_data_structure.AddressOfData, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)
            name_rva = hint_rva + 2
            hint_word = data[hint_rva: hint_rva + 2]
            name = get_string_from_data(data, name_rva)
            number_of_imports += 1
        thunks.append(thunk_data_structure)
        current_offset += thunk_data_structure.sizeof()
        rva += thunk_data_structure.sizeof()
        first_thunk_address += thunk_data_structure.sizeof()

    thunk_original = thunks[:]

    random_state = random.getstate()
    random.setstate(random_state)
    random.shuffle(thunks)

    first_thunk_data_original = first_thunk_data[:]
    random.setstate(random_state)
    random.shuffle(first_thunk_data)

    thunk_replacement_dict = {}
    for first_thunk, first_thunk_original in zip(first_thunk_data, first_thunk_data_original):
        thunk_replacement_dict[long(first_thunk)] = long(first_thunk_original)

    replacement_data = bytearray()
    for thunk, original in zip(thunks, thunk_original):
        replacement_data += thunk.__pack__()

    # Replace OFT Data
    data = data[:import_offset] + replacement_data + data[current_offset:]

    # Replace FT Data
    data = data[:ft_offset] + replacement_data + data[ft_offset + len(replacement_data):]

    for structure in optional_header_structure.DATA_DIRECTORY:
        if structure.name == 'IMAGE_DIRECTORY_ENTRY_BASERELOC':
            size = structure.Size
            rva = structure.VirtualAddress
            rlc_size = Structure(__IMAGE_BASE_RELOCATION_format__).sizeof()
            end = rva + size
            while rva < end:
                offset= get_pointer_from_rva(data, rva, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)

                data_reloc = data[offset: offset+rlc_size]
                rlc = Structure(__IMAGE_BASE_RELOCATION_format__, file_offset=0)
                rlc.__unpack__(data_reloc)

                if not rlc:
                    break

                block_data_rva = rva + rlc_size
                block_rva = rlc.VirtualAddress
                block_size = rlc.SizeOfBlock - rlc_size
                block_offset = get_pointer_from_rva(data, block_data_rva, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)
                block_data = data[block_offset: block_offset + block_size]

                for i in range (int(len(block_data) / 2)):
                    entry = Structure(__IMAGE_BASE_RELOCATION_ENTRY_format__, file_offset = i)
                    entry.__unpack__(block_data[i*2: (i+1)*2])
                    word = entry.Data
                    reloc_type = (word>>12)
                    reloc_offset = (word & 0xfff)

                    if reloc_type == 3:
                        dest = get_pointer_from_rva(data, block_rva, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)

                        dest += reloc_offset
                        unpacked_value = struct.unpack(byte_replacement_format, data[dest: dest + byte_replacement_size])[0]

                        dword_to_replace = unpacked_value- optional_header_structure.ImageBase

                        offset_to_search = dword_to_replace
                        if offset_to_search in thunk_replacement_dict:
                            replacement_data = struct.pack(byte_replacement_format, thunk_replacement_dict[offset_to_search] + optional_header_structure.ImageBase)
                            data[dest:dest + byte_replacement_size] = replacement_data

                    elif reloc_type == 10:
                        dest = get_pointer_from_rva(data, block_rva, structure_header, nt_headers_structure, file_header_structure, optional_header_structure)
                        dest += reloc_offset
                        unpacked_value = ctypes.c_ulonglong(struct.unpack(byte_replacement_format, data[dest: dest + byte_replacement_size])[0]).value

                        dword_to_replace = unpacked_value - ctypes.c_ulonglong(optional_header_structure.ImageBase).value
                        offset_to_search = dword_to_replace
                        if offset_to_search in thunk_replacement_dict:
                            replacement_data = struct.pack(byte_replacement_format, thunk_replacement_dict[offset_to_search] + optional_header_structure.ImageBase)
                            data[dest:dest + byte_replacement_size] = replacement_data
                rva += rlc.SizeOfBlock

    return bytes(data)

def main():
    parser = argparse.ArgumentParser(description="SCYTHE imphash modifier (32 bit)")
    parser.add_argument("--infile", help="File you wish to modify.", required=True)
    parser.add_argument("--outfile", help="Output file with modified imphash.", required=True)
    args = parser.parse_args()
    print "Old Imphash: " + pefile.PE(args.infile).get_imphash()
    data = open(args.infile, 'rb').read()
    data_replacement = modify_imphash(data)
    file_replacement = open(args.outfile, 'wb+')
    file_replacement.write(data_replacement)
    print "New Imphash: " + pefile.PE(args.outfile).get_imphash()


if __name__ == "__main__":
    main()