import idautils
import idaapi
import idc
import os

def get_decompilation(func_name):
    addr = idaapi.get_name_ea(idaapi.BADADDR, func_name)
    if addr == idaapi.BADADDR:
        return None
    try:
        decomp = idaapi.decompile(addr)
        return str(decomp) if decomp else None
    except:
        return None


if __name__ == "__main__":
    binary_path = idaapi.get_input_file_path()
    binary_dir = os.path.dirname(binary_path)
    os.chdir(binary_dir)
    
    prompt = ""
    func_names = idc.ARGV[1:]
    for func_name in func_names:
        decompiled_code = get_decompilation(func_name)
        if decompiled_code:
            prompt += f'Function {func_name} decompile code:\n{decompiled_code}\n'
        else:
            print(f"decompiled failed at: {func_name}")
    prompt += "Please continue taint analysis according to the provided function decompiled code."  
    with open("Unknown_Func.txt","w") as file:
        file.write(prompt) 
    idc.qexit(0)
    