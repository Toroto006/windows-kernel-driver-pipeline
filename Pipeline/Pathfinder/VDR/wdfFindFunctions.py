from idc import *
from idautils import *
from ida_hexrays import *
from ida_struct import *
import ida_typeinf, ida_auto, ida_loader, ida_idp, ida_kernwin
from wdfFunctionDict import wdf_functions_offsets
import time

def exit_without_change(status):

    print('-' * 50) # Differentiate the log

    # Not create/change idb
    process_config_line("ABANDON_DATABASE=YES")

    # Exit with the status code
    qexit(status)

# Ported from examples/hexrays/decompile_entry_points.py
def init_hexrays():
    
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    
    if not decompiler:
        error("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    
    if ida_loader.load_plugin(decompiler) and init_hexrays_plugin():
        return True
    else:
        error('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False

class wdf_function_finder_t(ctree_visitor_t):

    def __init__(self, only_function_names=True):
        if only_function_names:
            # no need for parents if we do not check them
            ctree_visitor_t.__init__(self, CV_FAST )
        else:
            ctree_visitor_t.__init__(self, CV_PARENTS )
        self.only_function_names = only_function_names
        self.found_functions = set()
    
    def get_functions(self):
        if self.only_function_names:
            return set(wdf_functions_offsets[m] for m in self.found_functions)
        else:
            return set([(addr, wdf_functions_offsets[m], d) for addr, m, d in self.found_functions])

    # Find lvar with type recursively 
    def get_local_var(self, expr, _type=None):
        var = None

        if expr.op == cot_var:
            var = expr.v.getv()

        elif expr.op in [cot_ref, cot_ptr, cot_cast]:
            var = self.get_local_var(expr.x)

        return var

    def visit_expr(self, e_target):
        # directly check for valid reference
        # doing all checks directly gives small speedup
        if e_target.x is not None and \
            ((e_target.op in [cot_memptr, cot_memref] and e_target.m in wdf_functions_offsets) or \
                (e_target.op == cot_add and e_target.y.op == cot_num and e_target.y.n._value in wdf_functions_offsets)) and \
            ((e_target.x.op == cot_obj and get_name(e_target.x.obj_ea) == "g_WDF_functions") or \
                (str(e_target.x.type).find('WDFFUNCTIONS') != -1)):

            m = e_target.m if e_target.op in [cot_memptr, cot_memref] else e_target.y.n._value
            #print(f'{expr.ea:#x}: Function {wdf_functions_offsets[m]} used {e_target.op in [cot_memptr, cot_memref]}.')
            if self.only_function_names:
                self.found_functions.add(m)
                return 0

            # check if in debug mode
            debug_mode = False
            try:    
                #pass
                expr_call = self.parent_expr()
                if e_target.is_call_object_of(expr_call):
                    if expr_call.a.size() > 1:
                        variables = [self.get_local_var(expr_call.a.at(i)) for i in range(1, expr_call.a.size())]
                        are_args = [var.is_arg_var for var in variables if var is not None]
                        debug_mode = all(are_args)
                # else:
                #     # sometimes the parent is not directly, but two up?
                #     # hits waaay to many...
                #     prt_list = list(reversed(self.parents))
                #     if len(prt_list) >= 2:
                #         prt = prt_list[1]
                #         if prt.op == cot_call:
                #             debug_mode = True
                
                #print(f"Parent_expr is {expr_call.ea:#x} with {debug_mode}")
            except Exception as e:
                if __debug__:
                    print(f"[E] Somehow an error for deciding if KMDF function call is a debug call: {str(e)}")

            self.found_functions.add((e_target.ea, m, debug_mode))
            # return 1 # cant early return, we might miss some

        return 0

checked_functions_for_func_use = set()
def run_wdf_functions_finder(ea, debug=False, only_function_names=True):
    func_ea = get_func_attr(ea, FUNCATTR_START)
    if func_ea in checked_functions_for_func_use:
        return set()
    checked_functions_for_func_use.add(func_ea)

    cfunc = None
    try:
        cfunc = decompile(func_ea)#, flags=DECOMP_NO_CACHE)
        if cfunc is not None:
            wif = wdf_function_finder_t(only_function_names)
            wif.apply_to_exprs(cfunc.body, None)
            return wif.get_functions()
        elif __debug__ and debug:
            print(f"[D] Not able to decompile {func_ea:#x}")
    except:
        if __debug__ and debug:
            print('[E] Decompilation of a function {:#x} failed'.format(ea))
    return set()

def main(timeit=False):
    global checked_functions_for_func_use
    checked_functions_for_func_use = set()
    if ida_kernwin.cvar.batch: # batch mode execution
        # Wait until the initial auto analysis is finished
        ida_auto.auto_wait()

        # We need to load the decompiler manually
        if not init_hexrays():
            if ida_kernwin.cvar.batch:
                exit_without_change(-1)

    # example with hardcoded ea_wdf_functions
    # i.e. .data location of g_WDF_functions 
    ea_wdf_functions = 0x014003E7F8
    #ea_wdf_functions = 0x0140003358 
    
    WDF_FIND_FUNCTIONS_TIMEOUT = 60
    found = set()
    start_time = time.time()
    only_function_names = False
    if ida_typeinf.idc_get_type(ea_wdf_functions) == '_WDFFUNCTIONS':
        print(f"Old type")
        for offset in wdf_functions_offsets.keys():
            for ref_ea in DataRefsTo(ea_wdf_functions + offset):
                found.update(run_wdf_functions_finder(ref_ea, only_function_names=only_function_names))
                if time.time() - start_time > WDF_FIND_FUNCTIONS_TIMEOUT:
                    # it takes waaay to long otherwise, the pipeline will not finish for any amount of drivers
                    break
    else:
        for ref in XrefsTo(ea_wdf_functions):
            found.update(run_wdf_functions_finder(ref.frm, only_function_names=only_function_names))
            if time.time() - start_time > WDF_FIND_FUNCTIONS_TIMEOUT:
                break
    
    if not timeit and not only_function_names:
        for at, name, d in sorted(found, key=lambda x: x[1]):
            print(f"At {at:#x} found {name}{' and maybe debug wrapper' if d else ''}")
        
        if [d for _, _, d in found].count(True) > 10:
            # if we got more than 90% of functions saying they have a debug wrapper
            print("This is a KMDF driver in DEBUG compiled.")
    
    if not timeit and only_function_names:
        for name in found:
            print(f"Found {name}")

    print(f"All done and {len(found)} found")
    
if __name__ == '__main__':
    # runs = 5
    # start_time = time.time()
    # for _ in range(0, runs):
    #     main(timeit=True)
    # end_time = time.time()
    # elapsed_time = (end_time - start_time) / runs
    # print(f"The execution takes around {elapsed_time} seconds ({runs} runs).")
    main()
