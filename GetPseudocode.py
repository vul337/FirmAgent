#coding=gbk
import idaapi
import idc
import ida_auto
import pickle 
import json
import os

ida_auto.auto_wait()

sink_list = []
            
def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def addr2pseudo(cfunc, addr):
    item = cfunc.body.find_closest_addr(addr)
 
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        print("Not found item line")
    y = y_holder.value()
    return y

def GetAddrCode(addr):
    func = idaapi.get_func(addr)
    if func is None:
        print(f"{hex(addr)} is not a effect addr")
    else:
        cfunc = idaapi.decompile(func)
        if cfunc is not None:
            y = addr2pseudo(cfunc, addr)
            if y is not None and 0 <= y < len(cfunc.pseudocode):
                for i, line in enumerate(cfunc.pseudocode):
                    if i == y:
                        linecode = idaapi.tag_remove(line.line)
                        return linecode
            else:
                print(f"addr2pseudo returned invalid line number {y} for address {hex(addr)}")
                       
def main():
    binary_path = idaapi.get_input_file_path()
    binary_dir = os.path.dirname(binary_path)
    os.chdir(binary_dir)
    
    sink_type = idc.ARGV[1]
    code_dict =  {}
    with open(f"callchains_{sink_type}.pkl", 'rb') as file:
        all_chains, all_points = pickle.load(file)              
    
    for fun_addr in all_chains:
        func = idaapi.get_func(fun_addr)
        if func is None:
            print(f"{hex(fun_addr)} is not a effect addr")
        else:
            cfunc = idaapi.decompile(func)
            code_dict[fun_addr] = str(cfunc) 
            
    for point in all_points:
        code_dict[point] = GetAddrCode(point)          
                    
    save_to_json(code_dict, f"./code_{sink_type}.json")
    idc.qexit(0)
        
if __name__ == "__main__":
    main()
    
    
