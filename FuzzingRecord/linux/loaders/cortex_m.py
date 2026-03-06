#!/usr/bin/env python3

import ida_bytes
import ida_funcs
import ida_idp
import ida_loader
import ida_offset
import idaapi
import idc

import json
import struct
from collections import namedtuple, defaultdict
from pathlib import Path


def read_word(li, architecture):
    bytes = li.read(architecture['word_size']) or b''
    if len(bytes) == architecture['word_size']:
        if architecture['endianness'] == 'little' and architecture['word_size'] == 4:
            return struct.unpack('<I', bytes)[0]
    return None


class VectorTable(namedtuple('VectorTable', ['SP_main', 'exception_handlers'])):

    def size(self, architecture):
        return architecture['word_size'] * (len(self.exception_handlers) + 1) # SP_main

    def alignment(self, architecture):
        result = 128
        while result < self.size(architecture):
            result *= 2
        return result

    def exception_vectors(self, architecture):
        '''Returns list of (table_offset, exception, entry_point) tuples.'''

        def _removeprefix(s, p):
            return s[len(p):] if s.startswith(p) else s

        return [
            (
                architecture['word_size'] * (index + 1),
                '' if entry_point == 0 else
                        _removeprefix(architecture['system_exceptions'][index], 'Reserved|') if index < len(architecture['system_exceptions']) else
                                'IRQ_{}'.format(index - len(architecture['system_exceptions'])),
                entry_point
            ) for index, entry_point in enumerate(self.exception_handlers)
        ]

    @staticmethod
    def probe(li, architecture):
        '''The resulting vector table can be bigger than the original.'''

        SP_main = read_word(li, architecture)
        if (SP_main is None
                or SP_main % 8 != 0
                or not int(architecture['memory_map']['SRAM']['start'], 0) <= SP_main < int(architecture['memory_map']['SRAM']['end'], 0)):
            return (None, 'Invalid stack pointer!')

        exception_handlers = []
        for index in range(len(architecture['system_exceptions']) + architecture['IRQs_supported']):

            entry_point = read_word(li, architecture)
            if entry_point is None:
                if index < len(architecture['system_exceptions']):
                    return (None, 'Invalid exception handler!')
                else:
                    break
            if entry_point == 0:
                if index < len(architecture['system_exceptions']):
                    if not architecture['system_exceptions'][index].startswith('Reserved'):
                        return (None, 'Invalid exception handler!')
            else:
                if index < len(architecture['system_exceptions']):
                    if architecture['system_exceptions'][index] == 'Reserved':
                        return (None, 'Invalid exception handler!')
                if entry_point & 1 != 1:
                    if index < len(architecture['system_exceptions']):
                        return (None, 'Invalid exception handler!')
                    else:
                        break
                entry_point ^= 1
                if not int(architecture['memory_map']['Code']['start'], 0) <= entry_point < int(architecture['memory_map']['Code']['end'], 0):
                    if index < len(architecture['system_exceptions']):
                        return (None, 'Invalid exception handler!')
                    else:
                        break

            exception_handlers.append(entry_point)

        return (VectorTable(SP_main, exception_handlers), None)


def align_down(address, alignment):
    return address - (address % alignment)


class Application(namedtuple('Application', ['base_address', 'vector_table'])):

    ALIGNMENT = 0x1000

    def _probe_dummy_exception_handlers(li):

        BYTE_PATTERNS = [
            b'\x70\x47', # BX LR
            b'\xFE\xE7', # B .
            b'\xFF\xF7\xFE\xBF', # B.W .
            b'\x00\xBF\xFE\xE7', # NOP B .
            b'\x2D\xF0\x07\x01', # BIC.W R1, SP, #7
        ]

        # Thumb instructions are either 16-bit or 32-bit, and are aligned on a two-byte boundary.
        assert li.tell() % 2 == 0

        result = []

        bytes_window = li.read(4) or b''
        while len(bytes_window) >= 2:
            for byte_pattern in BYTE_PATTERNS:
                if bytes_window.startswith(byte_pattern):
                    result.append(li.tell() - len(bytes_window))
            bytes_window = bytes_window[2:] + (li.read(2) or b'')
        
        return result

    def _probe_base_address(memory_addresses, file_addresses):

        MIN_CONFIDENCE = 15

        potential_base_address_confidence = defaultdict(int)
        for memory_address in memory_addresses:
            for file_address in file_addresses:
                potential_base_address = memory_address - file_address
                if potential_base_address % Application.ALIGNMENT == 0:
                    potential_base_address_confidence[potential_base_address] += 1
        if len(potential_base_address_confidence) > 0:
            most_confident_potential_base_address = max(potential_base_address_confidence, key=potential_base_address_confidence.get)
            if potential_base_address_confidence[most_confident_potential_base_address] >= MIN_CONFIDENCE:
                return most_confident_potential_base_address

        return None

    @staticmethod
    def probe(li, architecture):

        (vector_table, error_message) = VectorTable.probe(li, architecture)
        if vector_table is None:
            return (None, error_message)

        base_address = Application._probe_base_address(
                filter(lambda entry_point: entry_point != 0, vector_table.exception_handlers),
                Application._probe_dummy_exception_handlers(li))
        if base_address is None: # fallback
            reset_vector = vector_table.exception_handlers[0]
            base_address = align_down(reset_vector - vector_table.size(architecture), Application.ALIGNMENT)

        return (Application(base_address, vector_table), None)


DATA = json.load(open(Path(__file__).with_suffix('.json')))
for architecture in DATA['architectures']:
    architecture.update({ 'endianness': 'little', 'word_size': 4 })


def accept_file(li, filename):
    for architecture in DATA['architectures']:
        (vector_table, _) = VectorTable.probe(li, architecture)
        if vector_table is not None:
            return {
                'format': '{} ({}) binary file'.format(architecture['name'], architecture['extensions']),
                'processor': 'ARM:' + architecture['name']
            }
        else:
            li.seek(0)
    return 0


def align_up(address, alignment):
    return align_down(address + alignment - 1, alignment)

def add_32bit_segm(start, end, name, sclass):
    idaapi.add_segm(0, start, end, name, sclass)
    idc.set_segm_addressing(start, 1) # 32 bit segment addressing

def load_file(li, neflags, format):

    architecture = next(filter(lambda architecture:
            format == '{} ({}) binary file'.format(architecture['name'], architecture['extensions']), DATA['architectures']))
    (application, _) = Application.probe(li, architecture)

    idaapi.inf_set_app_bitness(32)
    idaapi.set_processor_type('ARM:' + architecture['name'], ida_idp.SETPROC_LOADER)

    li.file2base(0, application.base_address, application.base_address + li.size(), ida_loader.FILEREG_PATCHABLE)
    add_32bit_segm(application.base_address, application.base_address + li.size(), 'Code', 'CODE')
    idc.split_sreg_range(application.base_address, 'T', 1)

    ida_bytes.create_dword(application.base_address, architecture['word_size'])
    idc.set_name(application.base_address, 'SP_main', idc.SN_NOCHECK)

    for (table_offset, exception, entry_point) in application.vector_table.exception_vectors(architecture):
        if entry_point == 0:
            ida_bytes.create_dword(application.base_address + table_offset, architecture['word_size'])
        else:
            ida_offset.op_offset(application.base_address + table_offset, 0, idc.REF_OFF32)
            idc.set_cmt(application.base_address + table_offset, exception, False)
            if idc.get_name(entry_point) == '' or idc.get_name(entry_point).startswith('unk_'):
                ida_funcs.add_func(entry_point)
                idc.set_name(entry_point, exception + '_handler', idc.SN_NOCHECK | idc.SN_PUBLIC)

    add_32bit_segm(int(architecture['memory_map']['SRAM']['start'], 0),
            align_up(application.vector_table.SP_main, Application.ALIGNMENT), 'SRAM', 'DATA')

    add_32bit_segm(int(architecture['memory_map']['PPB']['start'], 0), int(architecture['memory_map']['PPB']['end'], 0), 'PPB', 'DATA')
    for component in DATA['components']:
        for register in component['registers']:
            if (int(architecture['memory_map']['PPB']['Non-secure SCS']['start'], 0) <= int(register['address'], 0)
                    and int(register['address'], 0) < int(architecture['memory_map']['PPB']['Non-secure SCS']['end'], 0)):
                idc.set_name(int(register['address'], 0), 'NS_' + register['name'], idc.SN_NOCHECK)
            else:
                idc.set_name(int(register['address'], 0), register['name'], idc.SN_NOCHECK)

    return 1

if __name__=='__main__':
    pass
