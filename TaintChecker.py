

class TaintEngine():
    def __init__(self, vul_type:str):
        self.vul_type = vul_type
        self.function_summaries= []

    def update_function_summary(self):
        for source_nm in self.sources_name_list:
            has_no_summary = True
            for fun_sum in self.function_summaries:
                assert isinstance(fun_sum)
                if source_nm in fun_sum.name:
                    has_no_summary = False
                    break


    def set_source_sink(self, additional_source_functions=None, additional_sink_functions=None):
        
        self.sources_name_list = ["websGetVar", "webGetVar", "j_websGetVar", "websGetVarN", "webGetVarString", "json_object_get_string", "get_cgi", "json_string_value"]
        
        self.sinks_name_list = ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "sscanf", "cmsUtl_strcpy", 
                                    "CsteSystem","system", "doSystemCmd", "twsystem", "doSystem", "popen", "execv", "execve",
                                    "FCGI_popen", "rut_doSystemAction"]
        
        self.ci_name_list = ["CsteSystem","system", '_system', "doSystemCmd", "twsystem", "doSystem", "popen"]
        
        self.bof_name_list = ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "sscanf", "cmsUtl_strcpy"]

    def add_source_functions(self, source_func_name:str):
        self.sources_name_list.append(source_func_name)

    def add_sink_functions(self, sink_func_name:str):
        self.sinks_name_list.append(sink_func_name)

    def update_source_function_addr(self, infos):
        new_function_summaries = []
        for func in self.function_summaries:
            has_addr = False
            for info in infos:
                if func.name in info:
                    func.addr = info[3].addr
                    has_addr = True
                    break

            if has_addr:
                new_function_summaries.append(func)

        self.function_summaries = new_function_summaries
