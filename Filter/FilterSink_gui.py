import ida_name
import idautils
import ida_hexrays
import ida_funcs
import ida_idaapi
import idc
import ida_ua
import ida_idp
import ida_nalt
import ida_xref
import ida_bytes
from collections import deque
import csv
import re
import idaapi
import ida_auto

ida_auto.auto_wait()

sink_function=['strcpy','sscanf','sprintf','popen',"CsteSystem", "system", '_system', "doSystemCmd", "twsystem", "doSystem"]    
type_3_list=['strcpy','memcpy']

DEBUG=False

def is_inBlock(ea, start, end):  
    if ea >= start and ea < end:
        return True
    else:
        return False

def get_block_succs(blocks):  
    succs = []
    for i in range(len(blocks)):
        succs.append([])

    for i in range(len(blocks)):
        bb_start = blocks[i][0]
        refs = idautils.CodeRefsTo(bb_start, 1)      
        
        for ref in refs:
            for j in range(len(blocks)):
                if is_inBlock(ref, blocks[j][0], blocks[j][1]):
                    succs[j].append(i)
    return succs

def trace_blocks(graph,start,depth):   
    paths=[]
    queue=deque([([start], 0)])
    if start==0:
        paths.append([0])
        return paths
    while queue:
        path, current_depth = queue.popleft()
        current_node = path[-1]
        if current_depth == depth or not list(graph.predecessors(current_node)):
            paths.append(path[::-1])
            continue
        for next_node in graph.predecessors(current_node):
            if next_node not in path:
                new_path = list(path)  
                new_path.append(next_node)
                queue.append((new_path, current_depth + 1))   
    return paths

def stack_variable_defination(func_code_list,number,variable):   
    for i in range(0,number):
        if variable in func_code_list[i]:
            def_end_number=len(func_code_list[i])
            if '//' in func_code_list[i]:
                def_end_number=func_code_list[i].find('//')
            arrays_pattern=re.compile(r'\[(\d+)\]')                
            arrays_length=arrays_pattern.findall(func_code_list[i][:def_end_number])
            if len(arrays_length)==1:
                return int(arrays_length[0])
            else:
                return 0
    return 0

def variable_filter(arg):         
    variable_address = idc.get_name_ea_simple(arg)        
    if variable_address == idc.BADADDR:
        return True    
    else:
        return False   

def op_constant(op,expr=None):
    if op == idaapi.cot_obj and expr is not None:  
        obj = expr.obj_ea
        seg = idaapi.getseg(obj)
        seg_name = idaapi.get_segm_name(seg)
        if seg_name == '.rodata' or seg_name == ".rdata" or seg_name == "LOAD":   
            return True
        else:
            return False
    elif op == idaapi.cot_ref and expr is not None:   
        if expr.x.op ==  idaapi.cot_idx and expr.x.x.op ==idaapi.cot_obj: 
            return True
        else:
            return False
    
    return op == idaapi.cot_num or op == idaapi.cot_fnum or op == idaapi.cot_str

def result_deal_func_type_1(address):         
    try:
        # Get function containing the address
        func = idaapi.get_func(address)
        if not func:
            print(f"Cannot get function for address {hex(address)}")
            return True
            
        cfunc = idaapi.decompile(func.start_ea)
        if not cfunc:
            print(f"Cannot decompile function at {hex(address)}")
            return True
            
        item = cfunc.body.find_closest_addr(address)
        if not item:
            return True
        expr = getattr(item, 'cexpr', None)
        if expr is None:
            return True

        x = getattr(expr, 'x', None)
        if x is None:
            return True

        try:
            callee_ea = x.obj_ea
        except Exception:
            return True

        name = idc.get_func_name(callee_ea)
        if not name:
            return True
        
        # Analyze different function types
        if name in ["system", '_system', "popen"]:   
            if expr.op == idaapi.cot_call:                
                input_arg = expr.a[0]
                if input_arg.op == idaapi.cot_cast:
                    if not op_constant(input_arg.x.op, input_arg.x):
                        return True  # Keep this sink (dangerous)
                else:
                    if not op_constant(input_arg.op, input_arg):
                        return True  # Keep this sink (dangerous)
            else:
                return False  # Filter out (all args are constants)
        
        elif name in ["CsteSystem", "doSystemCmd", "twsystem", "doSystem"]:   
            if expr.op == idaapi.cot_call:                
                arg_size = expr.a.size()
                for i in range(arg_size):
                    arg_expr = expr.a[i]
                    if arg_expr.op == idaapi.cot_cast:
                        if not op_constant(arg_expr.x.op, arg_expr.x):
                            return True  # Keep this sink (dangerous)
                    else:
                        if not op_constant(arg_expr.op, arg_expr):
                            return True  # Keep this sink (dangerous)
                return False
            else:
                return False
                
        elif name in ["strcpy"]:
            if expr.op == idaapi.cot_call:
                dest_arg = expr.a[0]
                if dest_arg.op != idaapi.cot_var:    # dest is not a variable (Filter)
                    return False
                    
                src_arg = expr.a[1]
                if src_arg.op == idaapi.cot_cast:
                    is_const = op_constant(src_arg.x.op, src_arg.x)
                else:
                    is_const = op_constant(src_arg.op, src_arg)
                    
                if is_const:
                    return False  # Filter out (constant source)
                else:
                    return True   # Keep this sink (dangerous)
            else:
                return False
                
        elif name in ["sscanf"]:
            if expr.op == idaapi.cot_call:
                arg_size = expr.a.size()
                has_var_arg = False
                for i in range(2, arg_size):  
                    arg = expr.a[i]
                    if arg.op == idaapi.cot_var:
                        has_var_arg = True
                        break
                if not has_var_arg:
                    return False 
                
                input_arg = expr.a[0]
                if input_arg.op == idaapi.cot_cast:
                    is_const = op_constant(input_arg.x.op, input_arg.x)
                else:
                    is_const = op_constant(input_arg.op, input_arg)
                    
                if is_const:
                    return False  # Filter out (constant input)
                else:
                    return True   # Keep this sink (dangerous)
            else:
                return False
                
        elif name in ["sprintf"]:
            if expr.op == idaapi.cot_call:
                dest_arg = expr.a[0]
                if dest_arg.op != idaapi.cot_var:    # dest is not a variable (Filter)
                    return False
                
                arg_size = expr.a.size()
                for i in range(2, arg_size):
                    arg_expr = expr.a[i]
                    if arg_expr.op == idaapi.cot_cast:
                        if not op_constant(arg_expr.x.op, arg_expr.x):
                            return True  # Keep this sink (dangerous)
                    else:
                        if not op_constant(arg_expr.op, arg_expr):
                            return True  # Keep this sink (dangerous)
                return False  # Filter out (all variable args are constants)
            else:
                return False
        else:
            print(f"  -> Unknown function {name}, keeping")
            return True
    except Exception as e:
        print(f"Error analyzing {hex(address)}: {e}")
        return True  

def get_full_statement_lines(cfunc, y):
    lines = cfunc.pseudocode
    total_lines = len(lines)
    collected = []
    bracket_count = 0
    started = False

    for i in range(y, total_lines):
        # 保留行两侧空格：仅用于匹配时�? strip，收�?/返回时保留原始空格�?
        raw_line = idaapi.tag_remove(lines[i].line)
        stripped = raw_line.strip()

        # 如果起始行没有命中目标调用，为避免拼出“从这里到函数末尾”的超长片段，直接返回该行�?
        if not started and i == y and ('sprintf' not in stripped and 'sscanf' not in stripped):
            collected.append(raw_line)
            break

        if 'sprintf' in stripped or 'sscanf' in stripped:
            started = True

        collected.append(raw_line)

        bracket_count += stripped.count('(')
        bracket_count -= stripped.count(')')

        if started and bracket_count <= 0:
            break

    # 用换行拼接，避免把缩�?/尾随空格以及行边界“压扁”�?
    return '\n'.join(collected)

def addr2pseudo(cfunc, addr):
    item = cfunc.body.find_closest_addr(addr)
    if not item:
        return None
 
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        print("Not found item line")
    y = y_holder.value()
    if y is not None and 0 <= y < len(cfunc.pseudocode):
        full_stmt = get_full_statement_lines(cfunc, y)
    return full_stmt

def has_string_format_specifier(format_string):
    """
    检查格式化字符串中是否包含可以接受字符串输入的格式化符
    包括�?%s, %[数字]s, %[width]s 等变�?
    """
    string_format_pattern = r'%[-+0 #*]*(\d+|\*)?(\.\d+|\.\*)?[hlL]?s'
    
    # 匹配 sscanf 特有�? %[...] 格式（字符集匹配�?
    scanset_pattern = r'%\[[^\]]+\]'
    
    if re.search(string_format_pattern, format_string):
        return True
    
    if re.search(scanset_pattern, format_string):
        return True
    
    return False


def _decode_bytes_maybe(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode('utf-8', errors='replace')
        except Exception:
            return value.decode(errors='replace')
    return value


def _strip_cast_and_refs(expr):
    """尽量�? (type)X / &X / *X 这类包装剥掉，落到真正的表达式上�?"""
    cur = expr
    for _ in range(8):
        if cur is None:
            break
        if getattr(cur, 'op', None) == idaapi.cot_cast:
            cur = cur.x
            continue
        if getattr(cur, 'op', None) in (idaapi.cot_ref, idaapi.cot_ptr):
            cur = cur.x
            continue
        break
    return cur


def _extract_cstring_from_cexpr(expr):
    """�? Hex-Rays cexpr 中提取字符串字面量（返回 str �? None）�?"""
    expr = _strip_cast_and_refs(expr)
    if expr is None:
        return None

    # 1) 直接字符串常�?
    if expr.op == idaapi.cot_str:
        s = getattr(expr, 'string', None)
        if s is not None:
            return _decode_bytes_maybe(s)
        # 某些版本没有 .string，可退化为打印文本（不保证稳定�?
        try:
            return str(expr)
        except Exception:
            return None

    # 2) obj 指向 .rodata 字符�?
    if expr.op == idaapi.cot_obj:
        ea = getattr(expr, 'obj_ea', idaapi.BADADDR)
        if ea != idaapi.BADADDR:
            return _decode_bytes_maybe(idc.get_strlit_contents(ea, -1, idc.STRTYPE_C))

    return None


class _CallAtEAVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, target_ea):
        super().__init__(ida_hexrays.CV_FAST)
        self.target_ea = target_ea
        self.call_expr = None

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call and getattr(expr, 'ea', None) == self.target_ea:
            self.call_expr = expr
            return 1
        return 0


def _extract_format_from_ctree(cfunc, call_ea, libc_func):
    """精确提取当前 call_ea 对应调用�? format 字符串（返回 str �? None）�?"""
    v = _CallAtEAVisitor(call_ea)
    v.apply_to(cfunc.body, None)
    call_expr = v.call_expr
    if call_expr is None or call_expr.op != idaapi.cot_call:
        return None

    # sscanf(src, fmt, ...) / sprintf(dst, fmt, ...)
    if len(call_expr.a) < 2:
        return None
    fmt_expr = call_expr.a[1]
    return _extract_cstring_from_cexpr(fmt_expr)

def result_deal_func_type_2(call_ea, libc_func):              
    result_flag = False
    function = idaapi.get_func(call_ea)
    if not function:
        print(f"Cannot get function for address {hex(call_ea)}")
        return True
    
    cfunc = idaapi.decompile(function.start_ea)
    
    if not cfunc:
        return True

    fmt = _extract_format_from_ctree(cfunc, call_ea, libc_func)
    if fmt is not None:
        print(f"Extracted format string (ctree): {fmt}")
        if has_string_format_specifier(fmt):
            print(f"Found vulnerable format string: {fmt}")
            return True
        print(f"No string format specifier found, filtering out")
        return False

    code = addr2pseudo(cfunc, call_ea)
    print(f"Decompiled code at {hex(call_ea)}: {code}")
    if not code:
        return True

    if libc_func == 'sscanf':
        pattern = r'sscanf\s*\(\s*[^,]+,\s*[^\"]*"((?:[^"\\]|\\.)*)"'
    else:
        pattern = r'sprintf\s*\(\s*[^,]+,\s*[^\"]*"((?:[^"\\]|\\.)*)"'

    format_strings = re.findall(pattern, code)
    print(f"Extracted format strings (regex): {format_strings}")
    if not format_strings:
        print("Format extraction failed; keeping sink conservatively")
        return True

    for format_string in format_strings:
        if has_string_format_specifier(format_string):
            print(f"Found vulnerable format string: {format_string}")
            return True
    print("No string format specifier found, filtering out")
    return result_flag


class StrcpyVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, ea, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.ea = ea
        self.cfunc = cfunc
        self.src_varname = None
        self.dst_varname = None

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call:
            func_ea = expr.x.obj_ea
            func_name = idaapi.get_func_name(func_ea)
            
            if func_name == "strcpy":
                if len(expr.a) == 2:
                    dst_expr = expr.a[0]  
                    src_expr = expr.a[1]  
                    
                    if dst_expr.op == ida_hexrays.cot_var:
                        self.dst_varname = self.cfunc.lvars[dst_expr.v.idx].name
                    
                    if src_expr.op == ida_hexrays.cot_var:
                        self.src_varname = self.cfunc.lvars[src_expr.v.idx].name
                    return 1  
        return 0

def get_strcpy_varnames(ea):  
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        print("Decompilation failed")
        return None, None

    visitor = StrcpyVisitor(ea, cfunc)
    visitor.apply_to(cfunc.body, None)

    return visitor.dst_varname, visitor.src_varname

def result_deal_func_type_3(refs_addr,Dangerous_function):  
    if Dangerous_function not in type_3_list:
        return True
    func_code=str(ida_hexrays.decompile(refs_addr))
    src_def_length=0
    dst_def_length=0
    arg_dst, arg_src=get_strcpy_varnames(refs_addr)
    if arg_src:   
        func_code_list=func_code.split('\n')
        number=func_code_list.index('')
        
        src_def_length=stack_variable_defination(func_code_list,number,arg_src)
        
        if 0 < src_def_length < 20:      
            return False
        else:
            if arg_dst:   
                dst_def_length=stack_variable_defination(func_code_list,number,arg_dst)
                if src_def_length>0 and dst_def_length>0 and src_def_length <= dst_def_length:
                    return False       
                else:
                    return True
            else:
                return True
    else:
        result=variable_filter(arg_src) 
        return result 
    
def is_dangerous(call_ea, Dangerous_function):
    if Dangerous_function in ['strcpy','memcpy','system','popen', "CsteSystem", '_system', "doSystemCmd", "twsystem", "doSystem"]:
                type1_result = result_deal_func_type_1(call_ea)
                type3_result = result_deal_func_type_3(call_ea, Dangerous_function)
                if type1_result and type3_result:   
                    return True
    elif Dangerous_function in ['sscanf', 'sprintf']:
        type1_result = result_deal_func_type_1(call_ea)
        type2_result = result_deal_func_type_2(call_ea, Dangerous_function)
        if type1_result and type2_result:      
            return True         

def Analysis_main(Dangerous_function):
    addr=ida_name.get_name_ea(ida_idaapi.BADADDR, Dangerous_function)
    refs=list(idautils.CodeRefsTo(addr,0))  
    
    dangerous_sinks = []  # Store dangerous sink points
    safe_sinks = []      # Store filtered out safe sink points
    
    for i in range(0,len(refs)):
        try:
            call_ea=refs[i]         
            if is_dangerous(call_ea, Dangerous_function):
                dangerous_sinks.append(hex(refs[i]))
                print(f'  -> DANGEROUS SINK: {hex(refs[i])}')
            else:
                safe_sinks.append(hex(refs[i]))
                print(f'  -> Filtered out: {hex(refs[i])}')
                
        except Exception as e:
            print(f'Error processing {hex(refs[i])}: {e}')
            continue
    
    return dangerous_sinks, safe_sinks

def output_results(results):
    """Output filtered sink points to files"""
    with open('sink_analysis_summary.txt', 'w') as file:
        file.write("=== SINK POINT FILTERING RESULTS ===\n\n")
        
        total_dangerous = 0
        total_safe = 0
        
        for func_name, (dangerous, safe) in results.items():
            file.write(f"{func_name}:\n")
            file.write(f"  Total references: {len(dangerous) + len(safe)}\n")
            file.write(f"  Dangerous sinks: {len(dangerous)}\n")
            file.write(f"  Filtered out: {len(safe)}\n")
            
            if len(safe) > 0:
                file.write("  Safe addresses:\n")
                for addr in safe:
                    file.write(f"    {addr}\n")
            
            if len(dangerous) > 0:
                file.write("  Dangerous addresses:\n")
                for addr in dangerous:
                    file.write(f"    {addr}\n")
            
            filter_rate = len(safe) / (len(dangerous) + len(safe)) * 100 if (len(dangerous) + len(safe)) > 0 else 0
            file.write(f"  Filter rate: {filter_rate:.2f}%\n\n")
            
            total_dangerous += len(dangerous)
            total_safe += len(safe)
        
        file.write("=== OVERALL SUMMARY ===\n")
        file.write(f"Total sink points found: {total_dangerous + total_safe}\n")
        file.write(f"Dangerous sinks: {total_dangerous}\n") 
        file.write(f"Safe sinks: {total_safe}\n")
        
        overall_filter_rate = total_safe / (total_dangerous + total_safe) * 100 if (total_dangerous + total_safe) > 0 else 0
        file.write(f"Overall filter rate: {overall_filter_rate:.2f}%\n")
        print(f"=== OVERALL SUMMARY ===\nTotal sink points found: {total_dangerous + total_safe}\nDangerous sinks: {total_dangerous}\nSafe sinks: {total_safe}Overall filter rate: {overall_filter_rate:.2f}%\n")
        

if __name__ == '__main__':
    print("Starting sink point analysis...")
    
    results = {}
    
    for sink_func in sink_function:    
        print(f"\n{'='*50}")
        print(f"Analyzing sink function: {sink_func}")
        print('='*50)
        
        dangerous_sinks, safe_sinks = Analysis_main(sink_func)
        if dangerous_sinks != [] and safe_sinks != []:
            results[sink_func] = (dangerous_sinks, safe_sinks)
        
    # Output all results
    output_results(results)
    
    print("\nSink point filtering analysis completed!")
    
    idc.qexit(0)