#!/usr/bin/env python3
import argparse
import os
import json
import idapro
from pathlib import Path
import ida_segment
import ida_idaapi
import ida_funcs
import ida_idp
import ida_auto
import ida_undo



class sig_hooks_t(ida_idp.IDB_Hooks):

    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.matched_funcs = set()

    def func_added(self, pfn):
        self.matched_funcs.add(pfn.start_ea)

    def func_deleted(self, func_ea):
        try:
            self.matched_funcs.remove(func_ea)
        except:
            pass

    def func_updated(self, pfn):
        self.matched_funcs.add(pfn.start_ea)

    def idasgn_loaded(self, sig_name):
        return print(f"Sig {sig_name} loaded")

    def dump_matches(self):
        for fea in self.matched_funcs:
            print(f"Matched function {ida_funcs.get_func_name(fea)}")


### List the segments for the loaded binary
def list_segments():
    nb_items = ida_segment.get_segm_qty()
    print("Segments number:",  nb_items)
    for i in range(0, nb_items):
        seg_src = ida_segment.getnseg(i)
        print(str(i+1) + ".")
        print("\tname:", ida_segment.get_segm_name(seg_src))
        print("\tstart_address:", hex(seg_src.start_ea))
        print("\tend_address", hex(seg_src.end_ea))
        print("\tis_data_segment:", ida_segment.get_segm_class(seg_src) == ida_segment.SEG_DATA)
        print("\tbitness:", seg_src.bitness)
        print("\tpermissions:",  seg_src.perm, "\n")

### Just call an existing python script
def run_script(script_file_name:str):
    if not os.path.isfile(script_file_name):
        print(f"The specified script file {script_file_name} is not a valid python script")
        return
    ida_idaapi.IDAPython_ExecScript(script_file_name, globals())


### Apply provided sig file name
def apply_sig_file(database_file_name:str, sig_file_name:str, sig_res_file:str):
    if not os.path.isfile(sig_file_name):
        print(f"The specified value {sig_file_name} is not a valid file name")
        return

    root, extension = os.path.splitext(sig_file_name)
    if extension != ".sig":
        print(f"The specified value {sig_file_name} is not a valid sig file")
        return

    # Install hook on IDB to collect matches
    sig_hook = sig_hooks_t()
    sig_hook.hook()

    # Start apply process and wait for it
    ida_funcs.plan_to_apply_idasgn(sig_file_name)
    ida_auto.auto_wait()

    matches_no = 0
    for index in range(0, ida_funcs.get_idasgn_qty()):
        fname, _, fmatches = ida_funcs.get_idasgn_desc_with_matches(index)
        if fname in sig_file_name:
            matches_no = fmatches
            break

    matches = {
        "total_matches": matches_no,
        "matched_functions": []
    }

    for fea in sig_hook.matched_funcs:
        matches['matched_functions'].append({ "func_name": ida_funcs.get_func_name(fea), "start_ea": hex(fea) })


    with open(sig_res_file, 'w') as jsonfile:
        json.dump(matches, jsonfile, indent=2)

    print(f"Total matches {matches_no} while applying {sig_file_name} on {database_file_name}, saved results to {sig_res_file}")

### Internal string to bool converter used for command line arguments
def str_to_bool(value:str):
    if isinstance(value, bool):
        return value
    if value.lower() in {'false', 'f', '0', 'no', 'n'}:
        return False
    elif value.lower() in {'true', 't', '1', 'yes', 'y'}:
        return True
    raise ValueError(f'{value} is not a valid boolean value')

# Parse input arguments
parser=argparse.ArgumentParser(description="IDA Python Library Demo")
parser.add_argument("-f", "--file", help="File to be analyzed with IDA", type=str, required=True)
parser.add_argument("-l", "--list-segments", help="List segmentes", type=str_to_bool, nargs='?', const=True, default=False)
parser.add_argument("-s", "--script-file-name", help="Execute an existing python script file", type=str, required=False)
parser.add_argument("-g", "--sig-file-name", help="Provide a signature file to be applied, requires also -o", type=str, required=False)
parser.add_argument("-o", "--sig-res-file", help="Signature file applying result json file, works only together with -g", type=str, required=False)
parser.add_argument("-p", "--persist-changes", help="Persist database changes", type=str_to_bool, nargs='?', const=True, default=True)

args=parser.parse_args()

if (args.sig_file_name is not None and args.sig_res_file is None) or (args.sig_file_name is None and args.sig_res_file is not None):
    print("error: '-g/--sig-file-name' and '-o/--sig-res-file' arguments must be specified together or none of them.\n")
    parser.print_help()
    exit(-1)

# Run auto analysis on the input file
print(f"Opening database {args.file}...")
idapro.open_database(args.file, True)

# Create an undo point
if ida_undo.create_undo_point(b"Initial state, auto analysis"):
    print(f"Successfully created an undo point...")
else:
    print(f"Failed to created an undo point...")

# List segments if required so
if args.list_segments:
    print("Listing segments...")
    list_segments()

# Run a script if one provided
if args.script_file_name is not None:
    print(f"Running script {args.script_file_name}...")
    run_script(script_file_name=args.script_file_name)

# Apply signature file if one provided
if args.sig_file_name is not None:
    print(f"Applying sig file {args.sig_file_name}...")
    apply_sig_file(database_file_name=args.file, sig_file_name=args.sig_file_name, sig_res_file=args.sig_res_file)

# Revert any changes if specified so
if not args.persist_changes:
    if ida_undo.perform_undo():
        print(f"Successfully reverted database changes...")
    else:
        print(f"Failed to revert database changes...")

# Let the idb in a consistent state, explicitly terminate the database
print("Closing database...")
idapro.close_database()
print("Done, thanks for using IDA!")