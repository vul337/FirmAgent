import json
from collections import deque
import ida_auto
import idaapi
import idautils
import idc
import os

ida_auto.auto_wait()

CI_SINKS = [
    "CsteSystem", "system", "_system", "doSystemCmd", "twsystem",
    "doSystem", "popen", "execv", "execve", "FCGI_popen", "rut_doSystemAction"
]
BOF_SINKS = ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "sscanf", "cmsUtl_strcpy"]


def op_constant(op, expr=None):
    if op == idaapi.cot_obj and expr is not None:
        obj = expr.obj_ea
        seg = idaapi.getseg(obj)
        seg_name = idaapi.get_segm_name(seg) if seg else ""
        return seg_name in {'.rodata', '.rdata', 'LOAD'}
    if op == idaapi.cot_ref and expr is not None:
        return op_constant(expr.x.op, expr.x)
    return op in {idaapi.cot_num, idaapi.cot_fnum, idaapi.cot_str}


def arg_constant(cfunc, address):
    item = cfunc.body.find_closest_addr(address)
    if item is None or item.cexpr is None:
        return False
    expr = item.cexpr
    try:
        name = idc.get_func_name(expr.x.obj_ea)
        if name in CI_SINKS:
            if expr.op != idaapi.cot_call:
                return False
            for index in range(expr.a.size()):
                arg_expr = expr.a[index]
                cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
                if not op_constant(cur.op, cur):
                    return True
            return False
        if name in ["strcpy", "cmsUtl_strcpy", "strcat"]:
            if expr.op != idaapi.cot_call or expr.a.size() < 2:
                return False
            arg_expr = expr.a[1]
            cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
            return not op_constant(cur.op, cur)
        if name == "sscanf":
            if expr.op != idaapi.cot_call or expr.a.size() < 1:
                return False
            arg_expr = expr.a[0]
            cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
            return not op_constant(cur.op, cur)
        if name == "sprintf":
            if expr.op != idaapi.cot_call:
                return False
            for index in range(2, expr.a.size()):
                arg_expr = expr.a[index]
                cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
                if not op_constant(cur.op, cur):
                    return True
            return False
        return True
    except Exception as err:
        print(f"[!] arg_constant exception @ {hex(address)}: {err}")
        return False


def _find_block_for_ea(flowchart, ea):
    for block in flowchart:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None


def _backward_reachable_blocks(func, sink_call_ea):
    flowchart = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
    sink_block = _find_block_for_ea(flowchart, sink_call_ea)
    if sink_block is None:
        return []
    queue = deque([sink_block])
    visited = {sink_block.id}
    blocks = []
    while queue:
        block = queue.popleft()
        blocks.append(block)
        for pred in block.preds():
            if pred.id not in visited:
                visited.add(pred.id)
                queue.append(pred)
    blocks.sort(key=lambda blk: blk.start_ea)
    return blocks


def _direct_caller_functions(func_start_ea):
    callers = set()
    for xref in idautils.CodeRefsTo(func_start_ea, 0):
        caller_func = idaapi.get_func(xref)
        if caller_func is not None:
            callers.add(caller_func.start_ea)
    return callers


def _backward_reachable_functions_with_graph(sink_caller_func_start):
    """
    BFS 向上追溯所有调用者，同时记录调用图（callee -> set of callers）。
    返回:
        visited: 所有可达函数地址集合
        call_graph: dict { callee_start -> set(caller_start) }，仅包含 visited 内的边
    """
    queue = deque([sink_caller_func_start])
    visited = {sink_caller_func_start}
    # callee -> callers（在 visited 范围内）
    call_graph = {}

    while queue:
        current = queue.popleft()
        callers = _direct_caller_functions(current)
        call_graph[current] = callers & visited  # 先只记录已知的，下面补全

        for pred_func in callers:
            if pred_func not in visited:
                visited.add(pred_func)
                queue.append(pred_func)

    # 补全 call_graph：重新建边（visited 内所有 callee -> caller）
    # called_by[func] = set of funcs in visited that call func
    called_by = {f: set() for f in visited}
    for func_start in visited:
        for caller in _direct_caller_functions(func_start):
            if caller in visited:
                called_by[func_start].add(caller)

    return visited, called_by


def _find_root_functions(visited, called_by):
    """
    在 visited 中找到没有任何 visited 内调用者的函数（即调用链顶端 / 入度为0的节点）。
    """
    roots = [f for f in visited if len(called_by.get(f, set())) == 0]
    return roots


def _backward_reachable_functions(sink_caller_func_start):
    """兼容旧接口，仅返回排序后的函数列表。"""
    visited, _ = _backward_reachable_functions_with_graph(sink_caller_func_start)
    return sorted(visited)


def _collect_sink_calls(sinks):
    sink_calls = []
    legacy_func_max_callsite = {}
    for sink_name in sinks:
        sink_ea = idc.get_name_ea_simple(sink_name)
        if sink_ea == idaapi.BADADDR:
            print(f"[-] Sink function '{sink_name}' not found in the binary.")
            continue
        for xref in idautils.CodeRefsTo(sink_ea, 0):
            func_start = idc.get_func_attr(xref, idc.FUNCATTR_START)
            if func_start == idaapi.BADADDR:
                continue
            func = idaapi.get_func(xref)
            if func is None:
                continue
            cfunc = idaapi.decompile(func)
            if cfunc is None:
                continue
            if not arg_constant(cfunc, xref):
                continue
            sink_calls.append(
                {
                    "sink_name": sink_name,
                    "sink_ea": sink_ea,
                    "callsite_ea": xref,
                    "caller_func_start": func_start,
                }
            )
            if func_start not in legacy_func_max_callsite:
                legacy_func_max_callsite[func_start] = xref
            else:
                legacy_func_max_callsite[func_start] = max(legacy_func_max_callsite[func_start], xref)
    return sink_calls, legacy_func_max_callsite


def _extract_sink_scope(sink_calls):
    scope = []
    for sink_call in sink_calls:
        sink_caller_start = sink_call["caller_func_start"]
        sink_caller_func = idaapi.get_func(sink_caller_start)
        if sink_caller_func is None:
            continue

        # ✅ 同时获取调用图，用于找根函数
        visited, called_by = _backward_reachable_functions_with_graph(sink_caller_start)
        reachable_func_starts = sorted(visited)

        reachable_funcs = []
        for func_start in reachable_func_starts:
            func = idaapi.get_func(func_start)
            if func is None:
                continue
            reachable_funcs.append(
                {
                    "func_start": func.start_ea,
                    "func_end": func.end_ea,
                    "func_name": idc.get_func_name(func.start_ea),
                }
            )

        # ✅ 找调用链顶端的根函数（入度为0）
        root_funcs = _find_root_functions(visited, called_by)

        scope.append(
            {
                "sink_name": sink_call["sink_name"],
                "sink_ea": sink_call["sink_ea"],
                "sink_callsite_ea": sink_call["callsite_ea"],
                "sink_caller_func_start": sink_caller_start,
                "sink_caller_func_end": sink_caller_func.end_ea,
                "sink_caller_func_name": idc.get_func_name(sink_caller_start),
                "reachable_functions": reachable_funcs,
                "root_functions": sorted(root_funcs),   # ✅ 新增：顶端函数列表
            }
        )
    return scope


def _write_legacy_sink_addr(ci_results, bof_results):
    with open('sink_addr.txt', 'w', encoding='utf-8') as file:
        ci_lines = [f"0x{key:X}..0x{value:X}" for key, value in ci_results.items()]
        bof_lines = [f"0x{key:X}..0x{value:X}" for key, value in bof_results.items()]
        all_lines = ci_lines + bof_lines
        file.write(','.join(all_lines))
    print('ci sink func:')
    for key, value in ci_results.items():
        print(f"0x{key:X}..0x{value:X},", end='')
    print('\nbof sink func:')
    for key, value in bof_results.items():
        print(f"0x{key:X}..0x{value:X},", end='')
    print()


def _write_sink_scope(scope_ci, scope_bof):
    addr_ranges = set()
    for item in scope_ci + scope_bof:
        reachable_funcs = item["reachable_functions"]
        if not reachable_funcs:
            continue

        sink_addr = item["sink_callsite_ea"]
        root_funcs = item.get("root_functions", [])

        if root_funcs:
            # ✅ 取所有根函数中地址最小的作为起点（对应调用链最顶端 A 的地址）
            start_addr = min(root_funcs)
        else:
            # fallback：退化到旧逻辑，取所有可达函数中最小地址
            start_addr = min(f["func_start"] for f in reachable_funcs)

        addr_ranges.add(f"0x{start_addr:X}..0x{sink_addr:X}")

    with open('sink_scope_addr.txt', 'w', encoding='utf-8') as file:
        file.write(','.join(sorted(addr_ranges)))
    print(f"[+] sink scope addr entries: {len(addr_ranges)}")


def main():
    binary_path = idaapi.get_input_file_path()
    binary_dir = os.path.dirname(binary_path)
    os.chdir(binary_dir)
    ci_calls, ci_legacy = _collect_sink_calls(CI_SINKS)
    bof_calls, bof_legacy = _collect_sink_calls(BOF_SINKS)

    scope_ci = _extract_sink_scope(ci_calls)
    scope_bof = _extract_sink_scope(bof_calls)
    
    # _write_legacy_sink_addr(ci_legacy, bof_legacy)
    _write_sink_scope(scope_ci, scope_bof)

    idaapi.qexit(0)


if __name__ == '__main__':
    main()