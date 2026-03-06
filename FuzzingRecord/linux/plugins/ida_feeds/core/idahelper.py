import os
import ida_funcs
import ida_idp
import ida_auto
import ida_undo
import ida_loader
import ida_diskio


class SigHooks(ida_idp.IDB_Hooks):
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
        print(f"{sig_name} loaded")



class IDA:
    def __init__(self):
        self.path = True

    @staticmethod
    def get_ida_sig_dir():
        return ida_diskio.idadir(ida_diskio.SIG_SUBDIR)

    @staticmethod
    def save_idb_copy(new_filename: str):
        try:
            if ida_loader.save_database(new_filename, 0):
                print(f"Database successfully saved to {new_filename}")
            else:
                print(f"Failed to save the database to {new_filename}")
        except Exception as e:
            print(f"An error occurred while saving the database: {e}")

    @staticmethod
    def get_applied_sigs():
        applied_sigs = []
        for i in range(ida_funcs.get_idasgn_qty()):
            signame, optlibs, nmatches = ida_funcs.get_idasgn_desc_with_matches(i)
            applied_sigs.append((signame, optlibs, nmatches))

        return applied_sigs

    @staticmethod
    def get_sig_name(file):
        return ida_funcs.get_idasgn_title(file)

    @staticmethod
    def create_undo(undo_point: str=b"Initial state, auto analysis"):
        if ida_undo.create_undo_point(undo_point):
            print(f"Successfully created an undo point...")
        else:
            print(f"Failed to created an undo point...")

    @staticmethod
    def perform_undo():
        if ida_undo.perform_undo():
            print(f"Successfully reverted database changes...")
        else:
            print(f"Failed to revert database changes...")

    @staticmethod
    def apply_with_undo(sig_file_name: str):
        IDA.create_undo()
        result = IDA.apply_sig_file(sig_file_name)
        IDA.perform_undo()

        return result

    @staticmethod
    def apply_sig_list(sig_list):
        for sig in sig_list:
            if not ida_funcs.plan_to_apply_idasgn(sig['path']):
                print(f"plan_to_apply_idasgn() failed for {sig['path']}")

        if not ida_auto.auto_wait():
            print(f"auto_wait() canceled")

        results = []
        applied = IDA.get_applied_sigs()
        for sig in sig_list:
            idx = next((i for i, applied_sig in enumerate(applied) if applied_sig[0] == sig['path']), None)
            results.append((applied[idx][0], applied[idx][2], sig['row']))
        return results

    @staticmethod
    def apply_sig_file(sig_file_name: str):
        if not os.path.isfile(sig_file_name):
            print(f"The specified value {sig_file_name} is not a valid file name")
            return

        root, extension = os.path.splitext(sig_file_name)
        if extension != ".sig":
            print(f"The specified value {sig_file_name} is not a valid sig file")
            return

        # Install hook on IDB to collect func_matches
        sig_hook = SigHooks()
        sig_hook.hook()

        # Start apply process and wait for it
        ret = ida_funcs.plan_to_apply_idasgn(sig_file_name)
        print(f"plan_to_apply_idasgn returned {ret}")

        wait = ida_auto.auto_wait()
        print(f"auto_wait returned {wait}")

        matches_no = 0
        for index in range(0, ida_funcs.get_idasgn_qty()):
            fname, _, fmatches = ida_funcs.get_idasgn_desc_with_matches(index)
            if fname in sig_file_name:
                matches_no = fmatches
                break

        matches = {
            "signature": sig_file_name,
            "matches": len(sig_hook.matched_funcs),
            "matched_functions": []
        }

        for fea in sig_hook.matched_funcs:
            func_details = f'<0x{fea:x}> {ida_funcs.get_func_name(fea)}'
            matches['matched_functions'].append(func_details)
            matches['matched_functions'] = sorted(matches['matched_functions'])

        sig_hook.unhook()

        return matches
