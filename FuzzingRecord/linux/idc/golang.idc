#include <idc.idc>

static main()
{
  load_and_run_plugin("golang",0);
}

static run_plugin_set_govers(ea, govers)
{
  load_and_run_plugin("golang", govers);
}

//Function below is a helper for the golang startup signatures
//it helps by finding the address of secondary startup signature

//Find the expected address of setg_gcc (secondary signature) from runtime.rt0_go
//go1.11-go1.12
//runtime_rt0_go+81                       jz      short no_cgo_init
//runtime_rt0_go+83                       mov     rcx, rdi
//runtime_rt0_go+86                       lea     rsi, setg_gcc
//----------------------------------------------------------------
//go1.13-go1.17
//runtime_rt0_go+81                       jz      short no_cgo_init
//runtime_rt0_go+83                       lea     rsi, setg_gcc
static x64_get_setg_gcc_ea(ea)
{
  auto func_ea;
  //go1.13-go1.17
  if ( create_insn(ea + 0x83) )
  {
    func_ea = get_first_dref_from(ea + 0x83);
    if ( func_ea != BADADDR )
      return func_ea;
  }
  //go1.11-go1.12
  if ( create_insn(ea + 0x86) )
  {
    func_ea = get_first_dref_from(ea + 0x86);
    if ( func_ea != BADADDR )
      return func_ea;
  }
  return ea;
}
