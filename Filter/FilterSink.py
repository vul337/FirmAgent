#coding=gbk
import idaapi
import idautils
import idc
import argparse
import os
import ida_segment
import ida_auto
import ida_hexrays
import ida_name
import ida_ua
import re
from FilterSink_gui import *

ida_auto.auto_wait()

def set_base_address(base_addr):
    seg = ida_segment.get_first_seg()   #idaapi.get_imagebase()=ida_segment.get_first_seg().start_ea
    ida_segment.rebase_program(base_addr - seg.start_ea, ida_segment.MSF_FIXONCE)
    
def list_library_functions():
    functions = []
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
            func_name = idc.get_func_name(funcea)
            if "nvram" in func_name.lower() and "set" in func_name.lower():
                functions.append((funcea, func_name))
    return functions

def find_function_calls(func_ea):
    xrefs = []
    for ref in idautils.CodeRefsTo(func_ea, 0):
        xrefs.append(ref)
    return xrefs

def addr2pseudo(cfunc, addr):
    item = cfunc.body.find_closest_addr(addr)
 
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        print("Not found item line")
    y = y_holder.value()
    return y


def get_arguments(func_ea):
    for _ in range(3):
        prev_addr = idc.prev_head(func_ea)
        prev_code = idc.generate_disasm_line(prev_addr, idc.GENDSM_FORCE_CODE)
        if "R0" in prev_code:
            return idc.get_strlit_contents(ida_bytes.get_dword(get_operand_value(prev_addr,1)), -1, 0)
        else:
            func_ea = prev_addr
    
    return None

def extract_string_in_quotes(text):
    pattern = r'\(.*?"([^"]*)"'
    match = re.search(pattern, text)
    if match:
        return match.group(1)
    else:
        return None
              
def main():
    binary_path = idaapi.get_input_file_path()
    binary_dir = os.path.dirname(binary_path)
    os.chdir(binary_dir)
    base_addr = int(idc.ARGV[1])
    set_base_address(base_addr)
    sink_set = set()

    with open(f'all_sink_addr_{idc.ARGV[2]}.txt', 'r') as file:
        sink_addr = file.read().split()
    sink_addr_list = [int(addr, 16) for addr in sink_addr]

    for target_address in sink_addr_list:             
        func = idaapi.get_func(target_address)
        if func is None:
            print(f"addr {hex(target_address)} no exist")
        else:
            cfunc = idaapi.decompile(func)
            if cfunc is None:
                print(f"[-] decompile failed: {hex(func.start_ea)}")
                continue
            sink = idc.get_operand_value(target_address, 0)
            sink_name = ida_name.get_name(sink)
            if is_dangerous(target_address, sink_name):
                sink_set.add(hex(target_address))
    if sink_set:
        with open(f"filter_sink_{idc.ARGV[2]}.txt", "w") as file:
            file.write(' '.join(sink_set))
            
            
    #Processing NVRAM Source    
    nvram_source = []    
    if os.path.exists("nvram_addr.txt"):        
        with open('nvram_addr.txt', 'r') as file:
            source_addr = file.read().split()
        code_dict = {}
        functions = list_library_functions()
        for func_ea, func_name in functions:
            #print(f"Function: {func_name} at {hex(func_ea)}")
            xrefs = find_function_calls(func_ea)
            for ref in xrefs:
                #print(f"  Called at {hex(ref)}")
                if arg := get_arguments(ref):
                    code_dict[hex(ref)] = arg.decode('utf-8')
        print(code_dict)
        
        source_addr_list = [int(addr, 16) for addr in source_addr]
        for point in source_addr_list:
            func = idaapi.get_func(point)
            if func is None:
                print(f"{hex(point)} is not a effect addr")
            else:
                cfunc = idaapi.decompile(func)
                y = addr2pseudo(cfunc, point)
                if y is not None and 0 <= y < len(cfunc.pseudocode):
                    for i, line in enumerate(cfunc.pseudocode):
                        if i == y:
                            code = idaapi.tag_remove(line.line)
                            break
                else:
                    print(f"addr2pseudo returned invalid line number {y} for address {hex(point)}")
            arg = extract_string_in_quotes(code)
            print(arg)
            if arg in code_dict.values():
                nvram_source.append(hex(point))
        
        with open("filter_nvram.txt",'w') as file:
            file.write(' '.join(nvram_source)) 
               
    idc.qexit(0)
        
        
if __name__ == "__main__":
    main()