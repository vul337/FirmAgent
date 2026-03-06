#coding=utf-8
import angr
import networkx
import pickle
import re
import os
import logging
import json
import datetime
import traceback
import LLMapi
from collections import Counter
from angr.knowledge_plugins.functions import Function
current_time = datetime.datetime.now()
formatted_date = current_time.strftime("%Y-%m-%d_%H-%M")

class Callchain():
    def __init__(self, sink_caller_function_addr:int, source_caller_function_addr: int):
        self.sink_caller_function_addr = sink_caller_function_addr
        self.source_caller_function_addr = source_caller_function_addr
        self.sink_addrs = set()
        self.source_addrs = set()
        self.call_chains = []               
        self.call_points = []               
    
class LLManalysis():
    def __init__(self, bin_name, vul_type, ida_function_addresses=None, project=None, cfg=None, function_summaries=None,
                 log_file_name=None, lazy=False, bin_dir=None):
        self.bin_name = bin_name
        self.vul_type = vul_type
        if not lazy:
            if not project and not cfg:
                project, cfg = self.preload_bin(bin_name, ida_function_addresses)
            self.bin_project = project
            self.arch = project.arch
            self.bin_cfg = cfg
        else:
            # Lazy mode: do not preload angr/cfg. Only LLM_analysis-related fields will be used.
            self.bin_project = None
            self.arch = None
            self.bin_cfg = None
        self.sources_info = None
        self.function_summaries = function_summaries
        self.log_file_name = log_file_name
        self.potential_paths = []
        self.sink_function_analysis_flags = []                
        self.source_function_analysis_flags = {}
        self.middle_function_analysis_flags = {}
        self.dynamic_source_contexts = {}
        self.bin_dir = bin_dir if bin_dir else ''
        
    def load_potential_paths_from_json(self, json_path):
        if not os.path.exists(json_path):
            # fallback: try current working directory
            if os.path.exists('potential_paths.json'):
                json_path = 'potential_paths.json'
            else:
                return False
        try:
            with open(json_path, 'r') as f:
                items = json.load(f)
            loaded = []
            for it in items:
                cc = Callchain(
                    sink_caller_function_addr=it['sink_caller_function_addr'],
                    source_caller_function_addr=it['source_caller_function_addr']
                )
                cc.sink_addrs = set(it.get('sink_addrs', []))
                cc.source_addrs = set(it.get('source_addrs', []))
                cc.call_chains = it.get('call_chains', [])
                cc.call_points = it.get('call_points', [])
                loaded.append(cc)
            self.potential_paths = loaded
            return True
        except Exception:
            return False

    def get_callers(self, address_f=None, name_f=None):
        to_analyze = []

        if address_f:
            if type(address_f) == int:  
                nodes = [x for x in self.bin_cfg.nodes() if x.addr == address_f]
                if nodes:
                    node = nodes[0]
                    preds =self.bin_cfg.get_predecessors(node)
                    to_analyze += [(p.function_address, p, name_f) for p in preds]

            else:
                nodes = [x for x in self.bin_cfg.nodes() if x.addr == address_f[0]]
                if nodes:
                    node = nodes[0]
                    preds =self.bin_cfg.get_predecessors(node)
                    to_analyze += [(p.function_address, p, address_f[2], node, address_f[1]) for p in preds]
                    
                    # in this case, although the plt section is existed, the program may not load function by plt
                    if not to_analyze:
                        for (i, angr_default_function) in self.bin_cfg.functions.items():
                            if angr_default_function.name == address_f[2] and angr_default_function.addr!= address_f[0]:
                                ext_addr = angr_default_function.addr
                                ext_node = [x for x in self.bin_cfg.nodes() if x.addr == ext_addr]
                                if ext_node:
                                    ext_node = ext_node[0]
                                    ext_preds = self.bin_cfg.get_predecessors(ext_node)
                                    to_analyze += [(p.function_address, p, address_f[2], node, address_f[1]) for p in ext_preds]
            return to_analyze
        
        if name_f.startswith("sub_"):
            func_addr = int(name_f.split('sub_')[1], 16)
            if func_addr not in self.bin_project.kb.functions.keys():
                func_addr += self.bin_project.loader.main_object.mapped_base   
            print('new source:', hex(func_addr))
            node = [x for x in self.bin_cfg.nodes() if x.addr == func_addr]
            if node:
                node = node[0]
                preds = self.bin_cfg.get_predecessors(node)
                to_analyze += [(p.function_address, p, name_f, node, self.bin_project.loader.main_object.binary_basename) for p in preds]
            return to_analyze
        
        else:
            return []
    
    def loggerfile(self, output, model, sink_type):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(f"{output}/debug_{os.path.basename(self.bin_dir)}_{sink_type}_{model}.log", mode='a')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.propagate = False
        logger.addHandler(file_handler)
        return logger

    def _get_node_point_addr(self, node):
        if 'mips' in self.arch.name.lower():
            return node.instruction_addrs[-2]
        return node.instruction_addrs[-1]

    def _get_source_point_addr(self, source_info, source_node):
        if len(source_info) > 3 and isinstance(source_info[3], int):
            return source_info[3]
        return self._get_node_point_addr(source_node)
    
    def extract_sink_from_content(self, content):
        matches = re.findall(r"\('vuln',\s*('0x[0-9a-fA-F]+'|'[^']+'|0x[0-9a-fA-F]+),\s*('0x[0-9a-fA-F]+'|'[^']+'|0x[0-9a-fA-F]+)\)", content)
        if matches:
            sinks = [(match[0].strip("'"),match[1].strip("'")) for match in matches]
            return sinks
        return None
    
    def extract_braces_content_as_dict(self, text):
        pattern = r'\{.*?\}'
        matches = re.findall(pattern, text, re.DOTALL)
        content = json.loads(matches[0])
        return content
    
    def shortest_call_chain_length(self, potential_path):
        return min(len(call_chain) for call_chain in potential_path.call_chains) 

    def is_subset(self, call_chain, analyzed_callchain):
        return set(analyzed_callchain).issubset(call_chain)
    
    def call_to_list(self, data, call_point):
        points = [f"({hex(point)}, {data[str(point)]})" for point in call_point]
        return ', '.join(points)
    
    def check_to_analysis(self, chain_points):
        if tuple(chain_points[0]) in self.source_function_analysis_flags:
            if self.source_function_analysis_flags[tuple(chain_points[0])] == '':
                return '' 
            result = self.source_function_analysis_flags[tuple(chain_points[0])]
        else:
            result = 'analysis'
        for point in map(tuple, chain_points[1:]):
            if point in self.middle_function_analysis_flags:
                if self.middle_function_analysis_flags[point] == '':
                    return ''  
        return result
    
    def has_controllable_parameters(self, to_analyze_points):
        pattern = r'\(([^)]*)\)'
        def is_controllable(content):
            content = content.strip()
            if content == '':
                return False
            try:
                int(content)
                return False
            except ValueError:
                if (content.startswith('"') and content.endswith('"')) or \
                (content.startswith("'") and content.endswith("'")):
                    return False
                return True 
        
        def analyze_parameters(param_string):
            params = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', param_string)
            return any(is_controllable(param) for param in params)
    
        return any(analyze_parameters(re.search(pattern, point).group(1)) for point in to_analyze_points)   
    
    def get_key_by_value(self, dictionary, value):
        for key, val in dictionary.items():
            if val == value:
                return key
        return None 

    @staticmethod
    def _norm_line(value):
        if value is None:
            return ''
        if not isinstance(value, str):
            return str(value).strip()
        return value.strip()

    @classmethod
    def _norm_set(cls, values):
        return {cls._norm_line(v) for v in values if v is not None}

    @classmethod
    def _norm_value_to_key_map(cls, mapping):
        # mapping: {key: value(str)} -> {value.strip(): key}
        out = {}
        for k, v in mapping.items():
            out[cls._norm_line(v)] = k
        return out

    @staticmethod
    def _format_prompt_value(value):
        if value in (None, '', [], {}):
            return ''
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, indent=2)

    def _build_dynamic_source_prompt(self, source_addrs):
        context_sections = []
        for source_addr in source_addrs:
            source_context = self.dynamic_source_contexts.get(source_addr)
            if not source_context:
                continue

            testcase = self._format_prompt_value(source_context.get('reachable_testcase'))
            if not testcase:
                continue

            section_lines = [f"Source point: {hex(source_addr)}"]
            section_lines.append(f"Reachable test case: {testcase}")
            context_sections.append('\n'.join(section_lines))

        if not context_sections:
            return ''

        return "Runtime context from fuzzing:\n" + "\n\n".join(context_sections) + "\n\n"
    
    def signle_potential_path(self, potential_path):
        source_addr = 0x4167CC
        sink_addr = 0x4167CC
        if potential_path.sink_caller_function_addr == sink_addr and potential_path.source_caller_function_addr == source_addr:
            return False
        else:
            return True              

    def LLM_analysis_FourRole(self, directory, sink_type, model_flag):
        logger = self.loggerfile(directory, model_flag)
        json_file = self.bin_dir + f'/code_{sink_type}.json'
        with open(json_file, 'r') as f:
            data = json.load(f)
        prompt_count = 0
        model = LLMapi.LLMAPITwo(logger, model_flag)
        
        sorted_potential_paths = sorted(self.potential_paths, key=self.shortest_call_chain_length)              
        for potential_path in sorted_potential_paths:        
            # if self.signle_potential_path(potential_path):
            #     continue
            if potential_path.sink_caller_function_addr in self.sink_function_analysis_flags:                 
                continue
            sources = {}                                                                        
            sinks = {}
            sorted_source_addrs = sorted(potential_path.source_addrs, reverse=True)             
            for source_addr in sorted_source_addrs:
                try:
                    sources[hex(source_addr)] = data[str(source_addr)]              
                except KeyError as e:
                    traceback.print_exc()
                    logger.exception(e)
            sorted_sink_addrs = sorted(potential_path.sink_addrs)
            for sink_addr in sorted_sink_addrs:                     
                try:
                    sinks[hex(sink_addr)] = data[str(sink_addr)]
                except KeyError as e:
                    traceback.print_exc()
                    logger.exception(e)
                    
            list_sources = [(k, v) for k,v in sources.items()]
            list_sinks = [(k, v) for k,v in sinks.items()]
            str_sink = ', '.join([str(sink) for sink in list_sinks])            
                
            index = 0                                   
            for call_chain in potential_path.call_chains:           
                try:         
                    index += 1   
                    if len(call_chain) > 3:
                        continue
                    if len(call_chain) == 1:                    
                        Need_analysis = False
                        had_analysis = []
                        analysis_count = 0
                        if analysis_count > 3:                  
                            continue
                        for addr_sink in list_sinks:           
                            ana_source = []
                            pseudocode = ''
                            sink = addr_sink[1]         
                            if sink.strip() not in had_analysis:
                                to_analyze_points = sink            
                                had_analysis.append(sink.strip())
                            else:
                                continue
                            sources_norm = self._norm_value_to_key_map(sources)
                            target_norm = self._norm_line(to_analyze_points)
                            for line in data[str(call_chain[0])].splitlines():          
                                pseudocode += line
                                pseudocode += '\n'
                                line_norm = self._norm_line(line)
                                if line_norm in sources_norm:
                                    souraddr = sources_norm.get(line_norm)
                                    if souraddr is not None:
                                        ana_source.append(str((souraddr, line_norm)))
                                if line_norm == target_norm:              
                                    break 
                            if not ana_source:
                                continue
                            if len(ana_source) > 4:                    
                                dataflow_prompt = "Function decompiled code:\n"+ pseudocode + '\n' + "Please extracting directly data dependencies code related to the sink point: " + str(addr_sink)
                                related_source = []
                                prompt_count += 2 
                                dataflow_dict = model.dataflow_agent(dataflow_prompt)   
                                if list(dataflow_dict.keys())[0].upper() == 'YES':          
                                    Need_analysis = True
                                dataflow_list = list(dataflow_dict.values())[0]
                                strip_dataflow_list = [string.strip() for string in dataflow_list]          
                                for addr,source in sources.items():
                                    if source.strip() in strip_dataflow_list:                   
                                        related_source.append(f"({addr}, {source})")
                                if related_source:
                                    str_related_source = ', '.join(related_source)
                                    pseudocode = '\n'.join(dataflow_list)
                                else:
                                    continue
                            else:
                                str_related_source = ', '.join(ana_source)
                            taint_prompt = "decompiled code:\n" + pseudocode + '\n\n' + "sources: " + str_related_source + '\n' + "sink: " + str(addr_sink) + "\nPlease determine precisely whether the taint parameter can propagate from the source to the sink."         
                            analysis_count += 1
                            prompt_count += 2 
                            vuln_content = model.taint_agent(taint_prompt)
                            if vuln_content:
                                vuln_info = self.extract_sink_from_content(vuln_content)
                                if vuln_info:
                                    self.sink_function_analysis_flags.append(potential_path.sink_caller_function_addr)
                                    with open(f"{directory}/vuln_{os.path.basename(self.bin_dir)}_{model_flag}.md",'a') as vuln_file:
                                        vuln_file.write(f"{vuln_info}\n")
                                    print(vuln_info)
                                    break
                            else:
                                continue 
                        if not Need_analysis:
                            self.sink_function_analysis_flags.append(potential_path.sink_caller_function_addr) 
                            
                    #cross-func
                    else:
                        analyzed_points = []
                        pseudocode = ''
                        ana_source = []
                        chain_points = potential_path.call_points[index-1]          
                        ana_flag = self.check_to_analysis(chain_points)
                        if  ana_flag == '':
                            continue
                        elif ana_flag == 'analysis':
                            to_analyze_points = [data[str(x)] for x in chain_points[0]]            
                            if not self.has_controllable_parameters(to_analyze_points):                    
                                logger.debug("The para is empty or integer: {to_analyze_points}\n")
                                self.source_function_analysis_flags[tuple(chain_points[0])] = ''
                                self.middle_function_analysis_flags[tuple(chain_points[0])] = ''
                                continue
                            to_analyze_points_norm = self._norm_set(to_analyze_points)
                            sources_norm = self._norm_value_to_key_map(sources)
                            analyzed_points = []
                            for line in data[str(call_chain[0])].splitlines():               
                                line_norm = self._norm_line(line)
                                if line_norm in to_analyze_points_norm:
                                    analyzed_points.append(line_norm)
                                if line_norm in sources_norm:
                                    souraddr = sources_norm.get(line_norm)
                                    if souraddr is not None:
                                        ana_source.append(str((souraddr, line_norm)))
                                pseudocode += line
                                pseudocode += '\n'
                                if set(analyzed_points) == to_analyze_points_norm:
                                    break
                            if not ana_source:
                                continue   
                            str_call = self.call_to_list(data, chain_points[0])
                            str_ana_source = ', '.join(ana_source)
                            cross_dataflow_prompt = "decompiled code:\n" + pseudocode + '\n' + "sources: " + str_ana_source + '\n' + "call points: " + str_call + "\nPlease determine whether there is a direct data flow between the source and the call point arguments."
                            prompt_count += 2 
                            str_dataflow_dict = model.cross_dataflow_agent(cross_dataflow_prompt)
                            if not str_dataflow_dict.startswith('{'):
                                dataflow_dict = self.extract_braces_content_as_dict(str_dataflow_dict) 
                            else:
                                dataflow_dict = json.loads(str_dataflow_dict)
                            if dataflow_dict and any(dataflow_dict.values()):                                       #ex {'0x1':[1,2]}
                                control_par = set()
                                for key,value in dataflow_dict.items():
                                    control_par.update(value)                           
                                    str_control_par = ','.join(map(str, control_par))
                                self.source_function_analysis_flags[tuple(chain_points[0])] = str_control_par        
                            else:
                                self.source_function_analysis_flags[tuple(chain_points[0])] = ''
                                print(f"{hex(call_chain[0])} hasn't dataflow to {hex(call_chain[1])}\n")
                                continue                               
                        else:
                            str_control_par = ana_flag
                                                               
                        to_continue = False
                        for i in range(1, len(chain_points)):
                            if tuple(chain_points[i]) in self.middle_function_analysis_flags:
                                str_control_par = self.middle_function_analysis_flags[tuple(chain_points[i])]
                                continue
                            else:
                                str_call = self.call_to_list(data, chain_points[i])
                                pseudocode = ''
                                to_analyze_points = [data[str(x)] for x in chain_points[i]]                    
                                if not self.has_controllable_parameters(to_analyze_points):                            
                                    self.source_function_analysis_flags[tuple(chain_points[i])] = ''
                                    self.middle_function_analysis_flags[tuple(chain_points[i])] = ''
                                    to_continue = True
                                    break
                                to_analyze_points_norm = self._norm_set(to_analyze_points)
                                analyzed_points = []
                                for line in data[str(call_chain[i])].splitlines():
                                    line_norm = self._norm_line(line)
                                    if line_norm in to_analyze_points_norm:
                                        analyzed_points.append(line_norm)
                                    pseudocode += line
                                    pseudocode += '\n'
                                    if set(analyzed_points) == to_analyze_points_norm:
                                        break
                                    
                                middle_dataflow_prompt = "decompiled code:\n" + pseudocode + '\n' + "controllable parameters site: " + f"[{str_control_par}]" + '\n' + "call points: " + str_call + "\nPlease determine whether there is a direct data flow between the controllable parameters and the call point arguments."
                                control_par = set()
                                prompt_count += 2 
                                str_dataflow_dict = model.middle_dataflow_agent(middle_dataflow_prompt) 
                                if not str_dataflow_dict.startswith('{'):
                                    dataflow_dict = self.extract_braces_content_as_dict(str_dataflow_dict)
                                else:
                                    dataflow_dict = json.loads(str_dataflow_dict)
                                if dataflow_dict and any(dataflow_dict.values()):                                      
                                    for key,value in dataflow_dict.items():
                                        control_par.update(value)
                                        str_control_par = ','.join(map(str, control_par)) 
                                    self.middle_function_analysis_flags[tuple(chain_points[i])] = str_control_par
                                else:
                                    self.middle_function_analysis_flags[tuple(chain_points[i])] = ''
                                    print(f"{hex(call_chain[i])} hasn't dataflow to call point {hex(call_chain[i+1])}\n")
                                    to_continue = True
                                    break
                        if to_continue:
                            continue         
                                            
                        to_analyze_points = list(sinks.values())
                        pseudocode = ''
                        to_analyze_points_norm = self._norm_set(to_analyze_points)
                        analyzed_points = []
                        for line in data[str(call_chain[-1])].splitlines():              
                            line_norm = self._norm_line(line)
                            if line_norm in to_analyze_points_norm:
                                analyzed_points.append(line_norm)
                            pseudocode += line
                            pseudocode += '\n'
                            if set(analyzed_points) == to_analyze_points_norm:
                                break 
                        taint_prompt ="decompiled code:\n" + pseudocode + '\n' + "controllable parameter site: " + f"[{str_control_par}]" + '\n' + "sink: " + str_sink + "\nPlease determine precisely whether the controllable parameters can propagate to the sink."
                        prompt_count += 2     
                        #file.write(taint_prompt + '\n\n')
                        vuln_content = model.crossfunc_taint_agent(taint_prompt)
                        if vuln_content:
                            vuln_info = self.extract_sink_from_content(vuln_content)
                            if vuln_info:
                                with open(f"{directory}/vuln_{os.path.basename(self.bin_dir)}_{model_flag}.md",'a') as vuln_file:
                                    vuln_file.write(f"{vuln_info}\n")
                                print(vuln_info)                                      
                            self.sink_function_analysis_flags.append(potential_path.sink_caller_function_addr)           
                            break                    
                        else:
                            continue              
                    logger.debug("\n-----------------A call_chain has analyszed-----------------------\n\n")
                                            
                except IndexError as e:
                    traceback.print_exc()
                    logger.exception(e)
                except Exception as e:
                    traceback.print_exc()
                    logger.exception(e)
                    
            logger.debug("\n-----------------A potential path has analyszed-----------------------\n\n")
        
        with open(f"{directory}/vuln_{os.path.basename(self.bin_dir)}_{model_flag}.md",'a') as vuln_file:
            vuln_file.write("Send {} prompts\n".format(prompt_count))                              
        print("Send {} prompts".format(prompt_count))   
        
    def extract_poc(self, text):
        pattern = r'POC:\s*(\{.*\})'
        match = re.search(pattern, text, re.DOTALL)
        if match:
            poc_content = match.group(0)  
            return poc_content
        else:
            return None
                 
                         
    def LLM_analysis(self, directory, sink_type, model_flag, binary):
        logger = self.loggerfile(directory, model_flag, sink_type)
        json_file = self.bin_dir + f'/code_{sink_type}.json'
        with open(json_file, 'r') as f:
            data = json.load(f)
        prompt_count = 0
        model = LLMapi.LLMAPIThree(logger, model_flag, sink_type, binary)
        
        sorted_potential_paths = sorted(self.potential_paths, key=self.shortest_call_chain_length)              
        for potential_path in sorted_potential_paths:        
            if potential_path.sink_caller_function_addr in self.sink_function_analysis_flags:                 
                continue
            # if potential_path.sink_caller_function_addr != 0x17740:
            #     continue 
            sources = {}
            sinks = {}
            sorted_source_addrs = sorted(potential_path.source_addrs, reverse=True)             
            for source_addr in sorted_source_addrs:
                try:
                    sources[hex(source_addr)] = data[str(source_addr)]              
                except KeyError as e:
                    traceback.print_exc()
                    logger.exception(e)
            sorted_sink_addrs = sorted(potential_path.sink_addrs)
            for sink_addr in sorted_sink_addrs:                     
                try:
                    sinks[hex(sink_addr)] = data[str(sink_addr)]
                except KeyError as e:
                    traceback.print_exc()
                    logger.exception(e)
                    
            list_sources = [(k, v) for k,v in sources.items()]
            list_sinks = [(k, v) for k,v in sinks.items()]
            str_sink = ', '.join([str(sink) for sink in list_sinks])            
                
            index = 0                                   
            call_chain = min(potential_path.call_chains, key=len)       
            try:         
                index += 1   
                    
                all_pseudocode = ""
                all_source_info = []
                chain_points = None
                if len(call_chain) > 1:
                    chain_points = potential_path.call_points[index-1]
                
                first_func_addr = call_chain[0]
                first_pseudocode = ""
                to_analyze_points = []
                ana_source = []
                
                if len(call_chain) == 1:
                    to_analyze_points = list(sinks.values())            
                else:
                    to_analyze_points = [data[str(x)] for x in chain_points[0]]
                
                analyzed_points = []
                to_analyze_points_norm = self._norm_set(to_analyze_points)
                sources_norm = self._norm_value_to_key_map(sources)
                for line in data[str(first_func_addr)].splitlines():
                    line_norm = self._norm_line(line)
                    if line_norm in to_analyze_points_norm:
                        analyzed_points.append(line_norm)
                    if line_norm in sources_norm:
                        souraddr = sources_norm.get(line_norm)
                        if souraddr is not None:
                            ana_source.append(f"({souraddr}, {line_norm})")
                    first_pseudocode += line + '\n'
                    if set(analyzed_points) == to_analyze_points_norm:
                        break
                        
                if not ana_source:
                    continue
                    
                str_source_info = ', '.join(ana_source)
                all_pseudocode += f"// Function at {hex(first_func_addr)} (source function)\n{first_pseudocode}\n"
                
                middle_call_info = ""
                if len(call_chain) > 1:
                    middle_call_info += f"Call points from {hex(call_chain[0])} to {hex(call_chain[1])}: {self.call_to_list(data, chain_points[0])}\n"
                    
                    for i in range(1, len(call_chain) - 1):
                        func_addr = call_chain[i]
                        pseudocode = ""
                        to_analyze_points = [data[str(x)] for x in chain_points[i]]
                        to_analyze_points_norm = self._norm_set(to_analyze_points)
                        analyzed_points = []
                        
                        for line in data[str(func_addr)].splitlines():
                            line_norm = self._norm_line(line)
                            if line_norm in to_analyze_points_norm:
                                analyzed_points.append(line_norm)
                            pseudocode += line + '\n'
                            if set(analyzed_points) == to_analyze_points_norm:
                                break
                                
                        all_pseudocode += f"\n// Function at {hex(func_addr)} (middle function)\n{pseudocode}\n"
                        middle_call_info += f"Call points from {hex(call_chain[i])} to {hex(call_chain[i+1])}: {self.call_to_list(data, chain_points[i])}\n"
                    
                    # 锟斤拷锟斤拷锟斤拷锟侥汇函锟斤拷
                    sink_func_addr = call_chain[-1]
                    sink_pseudocode = ""
                    sink_to_analyze = list(sinks.values())
                    sink_to_analyze_norm = self._norm_set(sink_to_analyze)
                    analyzed_sink_points = []
                    
                    for line in data[str(sink_func_addr)].splitlines():
                        line_norm = self._norm_line(line)
                        if line_norm in sink_to_analyze_norm:
                            analyzed_sink_points.append(line_norm)
                        sink_pseudocode += line + '\n'
                        if set(analyzed_sink_points) == sink_to_analyze_norm:
                            break
                            
                    all_pseudocode += f"\n// Function at {hex(sink_func_addr)} (sink function)\n{sink_pseudocode}\n"
                    if len(chain_points) >= len(call_chain):  # 确锟斤拷锟斤拷锟斤拷锟斤拷效
                        middle_call_info += f"Call points to sink function: {self.call_to_list(data, chain_points[len(call_chain)-1])}\n"
                
                dynamic_source_prompt = self._build_dynamic_source_prompt(sorted_source_addrs)

                taint_prompt = dynamic_source_prompt
                taint_prompt += "Decompiled code with sources and sinks across the call chain:\n"
                taint_prompt += all_pseudocode + '\n\n'
                taint_prompt += "Sources: " + str_source_info + '\n'
                if middle_call_info:
                    taint_prompt += "Call points information:\n" + middle_call_info
                taint_prompt += "Sink: " + str_sink + '\n'
                taint_prompt += """Please perform taint analysis only at this stage.
Use the decompiled code and the reachable test case from fuzzing only to judge whether external input can propagate from the identified source to the sink.
Consider taint aliasing during the analysis.
If taint propagation can be directly determined and cause a vulnerability, report alerts in the following format:
[('alert', source_addr, sink_addr), ...]
If no taint propagation is detected, return [].
Do not generate a PoC packet in this stage.
"""
                
                prompt_count += 1
                
                vuln_content = model.taint_agent(taint_prompt, prompt_count)

                if vuln_content:
                    vuln_info = self.extract_sink_from_content(vuln_content)
                    if vuln_info:
                        poc = self.extract_poc(vuln_content)
                        self.sink_function_analysis_flags.append(potential_path.sink_caller_function_addr)
                        with open(f"{directory}/vuln_{os.path.basename(self.bin_dir)}_{sink_type}_{model_flag}.md", 'a') as vuln_file:
                            vuln_file.write(f"{vuln_info}\n{poc}\n\n")
                        print(f'{vuln_info}\n{poc}\n')
                else:
                    if len(call_chain) == 1:
                        self.sink_function_analysis_flags.append(potential_path.sink_caller_function_addr)
                                        
                logger.debug("\n-----------------A call_chain has analyzed-----------------------\n\n")
                                        
            except IndexError as e:
                traceback.print_exc()
                logger.exception(e)
            except Exception as e:
                traceback.print_exc()
                logger.exception(e)
                    
            logger.debug("\n-----------------A potential path has analyzed-----------------------\n\n")
        
        with open(f"{directory}/vuln_{os.path.basename(self.bin_dir)}_{sink_type}_{model_flag}.md",'a') as vuln_file:
            vuln_file.write(f"Send {prompt_count} prompts\n")                              
        print("Send {} prompts".format(prompt_count))                        
                            
    def Augmented(self, cfg, directory):
        cg = cfg.functions.callgraph
        path = None
        for candidate_name in ("indirect_data.json", "Indirect_call.json"):
            candidate_path = os.path.join(directory, candidate_name)
            if os.path.exists(candidate_path):
                path = candidate_path
                break
        if path:
            with open(path,'r') as f:
                data = json.load(f)
            for funcea, icall_info in data.items():
                for addr, targets in icall_info.items():
                    for target in targets:
                        if target.startswith("0x"):
                            source_addr = int(addr, 16)
                            target_addr = int(target, 16)
                            source_node = cfg.get_any_node(source_addr, anyaddr=True)
                            target_node = cfg.get_any_node(target_addr, anyaddr=True)
                            if source_node and target_node:
                                cg.add_edge(int(funcea,16), int(target, 16))            
                                cfg.graph.add_edge(source_node, target_node)            
                            else:
                                print(f"There is no node in {addr} or {target}")
                        
        
    def get_callpoints(self, caller, callee):                  
        node = self.bin_cfg.model.get_any_node(callee, anyaddr=True)
        preds = list(self.bin_cfg.graph.predecessors(node))
        callers = []
        for pred in preds:
            if pred.function_address == caller and pred.instruction_addrs:                
                if 'mips' in self.arch.name.lower():
                    callers.append(pred.instruction_addrs[-2])
                else:
                    callers.append(pred.instruction_addrs[-1])
        return callers
    
    
    def get_potential_paths(self, args, sinks_info, sources_info):
        
        all_chains = set()         
        all_points = set()        
        potential_paths = []
        source_function_names = [] 
        sink_function_names = []
        all_chains_count = 0
        
        self.Augmented(self.bin_cfg, self.bin_dir)
        cg = self.bin_cfg.functions.callgraph
        
        for source_index, source_info in enumerate(sources_info):
            source_caller_function_addr = source_info[0]
            source_node = source_info[1]
            source_function_name = source_info[2]
            
            for sink_info_index, sink_info in enumerate(sinks_info):
                exist_path = False
                sink_caller_function_addr = sink_info[0]
                sink_node = sink_info[1]
                sink_function_name = sink_info[2]
                
                for potential_path in potential_paths:
                    if source_caller_function_addr == potential_path.source_caller_function_addr and sink_caller_function_addr == potential_path.sink_caller_function_addr:
                        exist_path = True               
                        break    

                if not exist_path:
                    potential_path = Callchain(source_caller_function_addr=source_caller_function_addr, sink_caller_function_addr = sink_caller_function_addr)
                    has_path = networkx.has_path(cg, source_caller_function_addr, sink_caller_function_addr) 

                if has_path or exist_path:
                    sink_point_addr = self._get_node_point_addr(sink_node)
                    source_point_addr = self._get_source_point_addr(source_info, source_node)
                    potential_path.sink_addrs.add(sink_point_addr)
                    potential_path.source_addrs.add(source_point_addr)
                    all_points.add(sink_point_addr)
                    all_points.add(source_point_addr)
                    source_function_names.append(source_function_name)
                    sink_function_names.append(sink_function_name)
                    
                    if not exist_path:                                                  
                        if source_caller_function_addr == sink_caller_function_addr:                        
                            potential_path.call_chains = [[source_caller_function_addr]]
                            all_chains.add(source_caller_function_addr)
                            all_chains_count += 1
                        else:
                            call_chains_list = list(networkx.all_simple_paths(cg, source_caller_function_addr, sink_caller_function_addr))
                            potential_path.call_chains = sorted([list(k) for k in set(map(tuple, call_chains_list))], key=len)      
                            all_chains_count += len(potential_path.call_chains)
                            for call_chain in potential_path.call_chains:
                                all_chains.update(call_chain)
                                call_points = []
                                for i in range(len(call_chain)-1):
                                    point = self.get_callpoints(call_chain[i], call_chain[i+1])
                                    all_points.update(point)
                                    call_points.append(point)   
                                potential_path.call_points.append(call_points)
                        potential_paths.append(potential_path)
        
        source_name_counter = Counter(source_function_names) 
        with open(self.bin_dir + f'/potential_paths_info_{args.type}.md', 'w') as file:
            file.write("Potential path source_function_name and occurrences:\n")
            for name, count in source_name_counter.items():
                file.write(f"  {name}: {count}\n")
            file.write("Potential path sink_function_name and occurrences:\n")
            sink_name_counter = Counter(sink_function_names)
            for name, count in sink_name_counter.items():
                file.write(f"  {name}: {count}\n")
            file.write(f"call_chains length: {all_chains_count}\nPotential path length: {len(potential_paths)}")
            print(f"call_chains length: {all_chains_count}\nPotential path length: {len(potential_paths)}")
                                      
        with open(f'{self.bin_dir}/callchains_{args.type}.pkl', 'wb') as file:              
            pickle.dump((all_chains, all_points), file)
        with open(f'{self.bin_dir}/potential_paths_{args.type}.pkl', 'wb') as file:
            pickle.dump(potential_paths, file)
        self.potential_paths = potential_paths
        return all_chains_count
    
    
    def get_ori_potential_paths(self, args, sinks_info, sources_info):
        
        all_chains = set()          
        all_points = set()          
        potential_paths = []
        source_function_names = [] 
        sink_function_names = []
        all_chains_count = 0
        
        self.Augmented(self.bin_cfg, self.bin_dir)
        cg = self.bin_cfg.functions.callgraph
        
        for source_index, source_info in enumerate(sources_info):
            source_caller_function_addr = source_info[0]
            source_node = source_info[1]
            source_function_name = source_info[2]
            
            for sink_info_index, sink_info in enumerate(sinks_info):
                exist_path = False
                sink_caller_function_addr = sink_info[0]
                sink_node = sink_info[1]
                sink_function_name = sink_info[2]
                
                for potential_path in potential_paths:
                    if source_caller_function_addr == potential_path.source_caller_function_addr and sink_caller_function_addr == potential_path.sink_caller_function_addr:
                        exist_path = True               
                        break    

                if not exist_path:
                    potential_path = Callchain(source_caller_function_addr=source_caller_function_addr, sink_caller_function_addr = sink_caller_function_addr)
                    has_path = networkx.has_path(cg, source_caller_function_addr, sink_caller_function_addr) 

                if has_path or exist_path:  
                    sink_point_addr = self._get_node_point_addr(sink_node)
                    source_point_addr = self._get_source_point_addr(source_info, source_node)
                    potential_path.sink_addrs.add(sink_point_addr)
                    potential_path.source_addrs.add(source_point_addr)
                    all_points.add(sink_point_addr)
                    all_points.add(source_point_addr)
                    source_function_names.append(source_function_name)
                    sink_function_names.append(sink_function_name)
                    
                    if not exist_path:                                                 
                        if source_caller_function_addr == sink_caller_function_addr:                        
                            potential_path.call_chains = [[source_caller_function_addr]]
                            all_chains.add(source_caller_function_addr)
                            all_chains_count += 1
                        else:
                            call_chains_list = list(networkx.all_simple_paths(cg, source_caller_function_addr, sink_caller_function_addr))
                            potential_path.call_chains = sorted([list(k) for k in set(map(tuple, call_chains_list))], key=len)       
                            all_chains_count += len(potential_path.call_chains)
                            for call_chain in potential_path.call_chains:
                                all_chains.update(call_chain)
                                call_points = []
                                for i in range(len(call_chain)-1):
                                    point = self.get_callpoints(call_chain[i], call_chain[i+1])
                                    all_points.update(point)
                                    call_points.append(point)   
                                potential_path.call_points.append(call_points)
                        potential_paths.append(potential_path)
        return all_chains_count

    def get_sinks_node(self, sink_addresses):
        sinks = []
        for sink_address in sink_addresses:
            sinks += self.get_callers(address_f=sink_address)
        #return sinks
        self.sinks_info = sinks
        return sinks

    def get_sources_node(self, source_functions_name=None, source_addresses=[]):
        sources = []
        for function_name in source_functions_name:
            sources += self.get_callers(name_f=function_name)

        for source_address in source_addresses:
            sources += self.get_callers(address_f=source_address)

        self.sources_info = sources
        return sources

    def preload_bin(self, binary_path:str, ida_function_addresses:list):

        print("Creating angr Project")
        project = angr.Project(binary_path, auto_load_libs=True)

        print("Creating binary CFG")
        try:
            bin_cfg = project.analyses.CFG(resolve_indirect_jumps=True,
                                cross_references=True,
                                force_complete_scan=False,
                                heuristic_plt_resolving = True,
                                normalize=False,
                                symbols=True)
        except Exception:
            traceback.print_exc()

        self.store_cfg(bin_cfg)
        self.store_angr_project(project)
        # print(project.loader.main_object.symbols)
        return project, bin_cfg

    def recover_symbol(self, functions_info):
        # for function_info in functions_info:
        #     addr = int(function_info.func_addr)
        #     name = function_info.func_name
        #     func = Function(self.bin_cfg.kb.functions, addr, name)
        #     if addr not in self.bin_cfg.kb.functions:
        #         self.bin_cfg.kb.functions[addr] = func
        #         self.bin_cfg.kb.functions._function_added(func)
                
        for(i, angr_default_function) in self.bin_cfg.functions.items():
            match_flag = False
            for function_info in functions_info:

                if angr_default_function.addr == int(function_info.func_addr):
                    if function_info.func_name.startswith('__imp_'):
                        break

                    if function_info.func_name.startswith('sub_'):
                        break

                    if angr_default_function.name.startswith('sub_'):
                        angr_default_function.name = function_info.func_name
                        
    def recover_plt(self, functions_info):
        plts = self.bin_project.loader.main_object.plt
        imports = self.bin_project.loader.main_object.imports
        for i, function in self.bin_cfg.functions.items():
            if function.is_plt == True:
                plts[function.name] = function.addr

                
    def get_function_address(self, obj, func_name):
        if obj.plt and func_name in obj.plt:
            return obj.plt[func_name]
    
        if func_name in self.bin_cfg.kb.functions:
            return self.bin_cfg.kb.functions[func_name].addr

    
    def lib_scan(self, add_sink_addrs, add_source_addrs, sinks_name_list, sources_name_list):           
        for obj in self.bin_project.loader.all_elf_objects:
            for func_name in sinks_name_list:
                addr = self.get_function_address(obj, func_name)
                if addr is not None:
                    add_sink_addrs.append((addr, obj.binary_basename, func_name))
        
        for obj in self.bin_project.loader.all_elf_objects:
            for func_name in sources_name_list:
                addr = self.get_function_address(obj, func_name)
                if addr is not None:
                    add_source_addrs.append((addr, obj.binary_basename, func_name))


    def store_angr_project(self, project):
        project._store(self.bin_name + '_angr')

    def store_cfg(self, bin_cfg):
        cfg_file = open(self.bin_name + '_cfg', 'wb')
        pickle.dump(bin_cfg, cfg_file, -1)
        cfg_file.seek(0)
        cfg_file.close()






