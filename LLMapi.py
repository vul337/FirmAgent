#coding=gbk
import logging
import requests
import json
import os
import re
import time
import subprocess

from abc import ABC, abstractmethod

class LLMInterface(ABC):
    def __init__(self, logger):
        self.logger = logger
        
    @abstractmethod
    def dataflow_agent(self, prompt):
        pass

    @abstractmethod
    def cross_dataflow_agent(self, prompt):
        pass

    @abstractmethod
    def middle_dataflow_agent(self, prompt):
        pass

    @abstractmethod
    def taint_agent(self, prompt, prompt_count=None):
        pass

    @abstractmethod
    def crossfunc_taint_agent(self, prompt):
        pass 

class LLMAPITwo(LLMInterface):
    def __init__(self, logger, model_flag):
        super().__init__(logger)
        if model_flag == "gpt-4o":
            self.model_url = "https://api.openai.com/v1/chat/completions"
            self.model = "gpt-4o"
            self.api_key = os.environ["Private_API_KEY"]
        if model_flag == "deepseek":
            self.model_url = "https://api.deepseek.com/chat/completions"
            self.model = "deepseek-chat"
            self.api_key = os.environ["Private_API_KEY"]
        if model_flag == "kimi":
            self.model_url = "https://api.moonshot.cn/v1/chat/completions"
            self.model = "moonshot-v1-8k"
            self.api_key = os.environ["Private_API_KEY"]
            
        self.alert_content = """
            As an expert in program analysis and taint analysis, your task is to analyze the given code snippet and determine if there is a direct data flow between the specified {source} and {sink} variables. {parameter}. When analyzing taint propagation, distinguish between two scenarios:

            1. Direct data flow: The taint parameter's value directly becomes part of the sink parameter's content.
            2. Indirect control flow: The taint parameter is used in conditional statements to select other predefined values for the sink parameter.

            Analysis Steps
            Trace the data flow from the {source} to {sink}, Report a potential vulnerability only for the first scenario.
            Provide the alert in the format [('alert', {source_addr}, sink_addr)...].
            """
            
        self.taint_content = """
            As an expert in program analysis and taint analysis, your task is to analyze the given code snippet and determine if there is a direct data flow between the specified {source} and {sink} variables. When analyzing taint propagation, distinguish between two scenarios:

            1. Direct data flow: The taint parameter's value directly becomes part of the sink parameter's content.
            2. Indirect control flow: The taint parameter is used in conditional statements to select other predefined values for the sink parameter.

            Analysis Steps
            Trace the data flow from the {source} to {sink} in the first scenario, exclude the data flow propagated in the second scenario.
            """
        if model_flag == "gpt-4o":    
            self.validation = """
Looking at the above analysis, carefully analyze whether alerts are real vulnerabilities or false positives. Mainly consider the following false positives:
1. Sink point parameter passed by constants, such as strcpy(v4, "wl nrate -m 32");system(v4); passing the "wl nrate -m 32" constant string.This is a false positive.
2. The controllable parameter is an integer. Such as v3 = (const char *)nvram_get1((int)"WPSTimeout");v4 = atoi(v3);sprintf(v6, "killall um_autopind; um_autopind %d &", v4);system(v6); The controllable part of string v6 is an integer. This is a false positive.
3. The taint parameter is processed by the harmless function. Such as atoi(), is_vaild_ip(), isValidIpAddr(), isalpha() and so on. Although the sink point parameter is tainted, this is a false positive.
4. The tainted parameter comes from a system file, e.g. stream = fopen(��/etc/paawd��, ��r��); fgets(s, 256, stream); system(s); In this case, the value of stream comes from "/etc/paawd" and is assigned to the parameter s. This is a false positive.
Think step by step, returns alerts that are not false positives. Return format is [('vuln', {source_addr}, sink_addr)...], otherwise, return an empty list.
"""
        else:
            self.validation = """
Carefully review each alert and determine if it's a false positive based on these specific criteria:

Harmless function processing:
Example: input = get_user_input(); safe_val = atoi(input); snprintf(cmd, sizeof(cmd), "cmd %d", safe_val); system(cmd);
Rule: If the tainted input is processed by atoi(), is_valid_ip(), isValidIpAddr(), or similar functions, Although subsequently used to construct the command string, it's a FALSE POSITIVE.
IMPORTANT: atoi() and similar functions (atol, atoll, strtol, strtoll) ALWAYS produce a FALSE POSITIVE.


Constant parameters:

Example: strcpy(v4, "wl nrate -m 32"); system(v4);
Rule: If the sink function (e.g., system()) receives a constant string, it's a FALSE POSITIVE.


System file sources:

Example: FILE *f = fopen("/etc/passwd", "r"); fgets(buf, sizeof(buf), f); system(buf);
Rule: If the tainted data comes directly from a system file, it's a FALSE POSITIVE.



Instructions:

Examine each alert against these criteria.
If an alert matches ANY of these criteria, it MUST be classified as a false positive.
If atoi() or similar functions are used, must treat it strictly as a false positive and do not make your own associations.
Only return alerts that do NOT match any of these criteria.

Return format:

For real vulnerabilities: [('vuln', {source_addr}, sink_addr), ...]
If all alerts are false positives: [] (empty list)
"""
    
    def clean_and_parse_json(self, response):
        # clean Markdown
        json_string = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_string:
            json_string = json_string.group(1)
        else:
            json_string = response
        return json_string
     
    def extract_alert_from_content(self, content):
        matches = re.search(r"\('alert',\s*('0x[0-9a-fA-F]+'|'[^']+'|0x[0-9a-fA-F]+),\s*('0x[0-9a-fA-F]+'|'[^']+'|0x[0-9a-fA-F]+)\)", content)
        if matches:
            return True
        else:
            return False
    
    def send_prompt(self, messages, response_format=None):
        payload = {
            "model": self.model,
            "messages": messages
        }
        if response_format:
            payload["response_format"] = response_format
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.api_key}"
        }
        max_retries = 5
        retry_delay = 1
        for attempt in range(max_retries):
            try:
                response = requests.post(self.model_url, headers=headers, json=payload)
                response.raise_for_status()
                return response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)

        self.logger.debug("Max retries reached without successful response")
        return None
        
    def dataflow_agent(self, prompt):
        system_message = {
            "role":"system",
            "content":"""
                You are an expert in program analysis. Please according to the provided function decompile code and sink point, extracting directly data dependencies code related to specified sink point. Pay attention to the data alias and tainted data operations. Then analyze whether the sink point argument and the current function parameters have direct data dependencies. Please think step by step. 
            """    
        }
        user_message = {
            "role": "user",
            "content": prompt
        }
        self.logger.debug(f"signle_function dataflow_prompt:\n{prompt}\n\n")
        initial_messages = [system_message, user_message]
        response = self.send_prompt(initial_messages)
        self.logger.debug(f"signle_function dataflow analysis:\n{response}\n")
        if response:
            #Fommatted-output   
            output_prompt = """Based on the above analysis results, extract the corresponding data dependency code. If the sink point parameter has a direct data dependency with the current function parameter, the dictionary key value is YES, otherwise it is NO. Return it in json format. For example: {"NO":["v0 = nvram_get(\"wifi\");",\n"system(v0)"\n]}. Please ensure that the extracted code snippet belongs to the decompile code and the code in it cannot be modified."""
            self.logger.debug(f"signle_function dataflow output prompt:\n{output_prompt}\n")
            assistant_message = {
                "role": "assistant",
                "content": response,
            }
            format_request_messages = [
                system_message,
                user_message,
                assistant_message,
                {"role": "user", "content": output_prompt}
            ]
            response = self.send_prompt(format_request_messages, response_format={"type": "json_object"})
            if response:
                self.logger.debug(f"signle_function dataflow result:\n{response}\n")
                if not response.startswith("{"):
                    response = self.clean_and_parse_json(response)
                dataflow_dict = json.loads(response)
                return dataflow_dict

        
    def cross_dataflow_agent(self, prompt):
        source = "sources"
        sink = "call points"
        parameter = ""
        system_message = {
            "role":"system",
            "content":self.taint_content.format(source=source, sink=sink)
        }
        user_message = {
            "role": "user",
            "content": prompt
        }
        self.logger.debug(f"cross_funtion dataflow_prompt:\n{prompt}\n\n")
        initial_messages = [system_message, user_message]
        response = self.send_prompt(initial_messages)
        self.logger.debug(f"cross_funtion dataflow analysis:\n{response}\n")
        
        #Fommatted-output
        if response:   
            output_prompt = "Based on the above analysis results, please determine which arguments in the call point are tainted. {0x1: [1,2]} indicates that the first and second arguments of the call point with address 0x1 is tainted. Return result in a json format. For example, {0x1: [1,2]}. If there is no data flow between the source and the call point, return a empty dict {}." 
            self.logger.debug(f"cross_funtion dataflow output prompt:\n{output_prompt}\n")
            assistant_message = {
                "role": "assistant",
                "content": response,
            }
            format_request_messages = [
                system_message,
                user_message,
                assistant_message,
                {"role": "user", "content": output_prompt}
            ]
            response = self.send_prompt(format_request_messages, response_format={"type": "json_object"})
            self.logger.debug(f"cross_funtion dataflow result:\n{response}\n")
            return response
        
    def middle_dataflow_agent(self, prompt):
        source = "controllable parameters"
        sink = "call points"
        parameter = "Such as controllable parameter site: [1,2], indicating that the first and second parameters in the function are controllable."
        system_message = {
            "role":"system",
            "content":self.taint_content.format(source=source, sink=sink, parameter=parameter)
        }
        user_message = {
            "role": "user",
            "content": prompt
        }
        self.logger.debug(f"middle_funtion dataflow_prompt:\n{prompt}\n\n")
        initial_messages = [system_message, user_message]
        response = self.send_prompt(initial_messages)
        self.logger.debug(f"middle_funtion dataflow analysis:\n{response}\n")
        
        #Fommatted-output
        if response:
            output_prompt = "Based on the above analysis results, please determine which parameters in the call point are tainted. {0x1: [1,2]} indicates that the first and second parameters of the call point with address 0x1 is tainted. Return result in a json format. For example, {0x1: [1,2]}. If there is no data flow between the source and the call point, return a empty dict {}."
            self.logger.debug(f"middle_dataflow output prompt:\n{output_prompt}\n")
            assistant_message = {
                "role": "assistant",
                "content": response,
            }
            format_request_messages = [
                system_message,
                user_message,
                assistant_message,
                {"role": "user", "content": output_prompt}
            ]
            response = self.send_prompt(format_request_messages, response_format={"type": "json_object"})
            self.logger.debug(f"middle_funtion dataflow result:\n{response}\n")
            return response
    
    def taint_agent(self, prompt):
        source = "sources"
        sink = "sinks"
        parameter=""
        source_addr = "source_addr"
        system_message = {
            "role":"system",
            "content":self.alert_content.format(source=source, sink=sink, parameter=parameter, source_addr=source_addr)
        }
        user_message = {
            "role": "user",
            "content": prompt
        }
        self.logger.debug(f"signle_function taint analysis prompt:\n{prompt}\n\n")
        initial_messages = [system_message, user_message]
        response = self.send_prompt(initial_messages) 
        self.logger.debug(f"signle_function alert analysis result:\n{response}\n\n")
        alert = self.extract_alert_from_content(response)
        # self_validation
        if alert:
            self_validation_prompt = self.validation.format(source_addr=source_addr)
            self.logger.debug(f"signle_function self_validation prompt:\n{self_validation_prompt}\n")
            assistant_message = {
                "role": "assistant",
                "content": response,
            }
            format_request_messages = [
                system_message,
                user_message,
                assistant_message,
                {"role": "user", "content": self_validation_prompt}
            ]
            response = self.send_prompt(format_request_messages)
            self.logger.debug(f"signle_function vuln analysis result:\n{response}\n")
            return response
        
    def crossfunc_taint_agent(self, prompt):
        source = "controllable parameters"
        sink = "sinks"
        parameter = "Such as controllable parameter site: [1,2], indicating that the first and second parameters in the function are controllable."
        source_addr = "function_addr"
        system_message = {
            "role":"system",
            "content": self.alert_content.format(source=source, sink=sink, parameter=parameter, source_addr=source_addr)
        }
        user_message = {
            "role": "user",
            "content": prompt
        }
        self.logger.debug(f"cross_function taint analysis prompt:\n{prompt}\n\n")
        initial_messages = [system_message, user_message]
        response = self.send_prompt(initial_messages) 
        self.logger.debug(f"cross_function alert analysis result:\n{response}\n\n")
        alert = self.extract_alert_from_content(response)
        # self_validation
        if alert:
            self_validation_prompt = self.validation.format(source_addr=source_addr)
            self.logger.debug(f"cross_function self_validation prompt:\n{self_validation_prompt}\n")
            assistant_message = {
                "role": "assistant",
                "content": response,
            }
            format_request_messages = [
                system_message,
                user_message,
                assistant_message,
                {"role": "user", "content": self_validation_prompt}
            ]
            response = self.send_prompt(format_request_messages)
            self.logger.debug(f"cross_function vuln analysis result:\n{response}\n")
            return response
        
        

class LLMAPIThree(LLMInterface):
    def __init__(self, logger, model_flag, type, binary):
        super().__init__(logger)
        if model_flag == "R1_official":
            self.model_url = "https://api.deepseek.com/chat/completions"
            self.model = "deepseek-reasoner"
            self.api_key = os.environ["Private_API_KEY"]
        if model_flag == "V3_official":
            self.model_url = "https://api.deepseek.com/chat/completions"
            self.model = "deepseek-chat"
            self.api_key = os.environ["Private_API_KEY"]
            
            
        self.binary_dir = os.path.dirname(binary)
        self.binary = binary
            
        self.taint_content = """
            You are a taint analysis expert.
            """
        if type == "bof":
            self.validation = """
Looking at the above analysis, carefully analyze whether alerts are real buffer overflow vulnerabilities or false positives. Mainly consider the following false positives:
1. Fixed-size buffer with constant input: If the data written to the buffer is a constant string and does not exceed the buffer size, such as char buf[16]; strcpy(buf, "fixed_string");, then it is a false positive.
2. The length of the input is explicitly checked before writing to the buffer: If strlen, sizeof, memcpy with length checks, or other validation mechanisms are used before copying data to a buffer, such as if (strlen(src) < sizeof(dest)) strcpy(dest, src);, then this is a false positive.
3. The source of data is a system-configured or static file with controlled length: If data comes from a fixed system file with a predefined format and length, such as fgets(buf, 32, fopen("/proc/cmdline", "r"));, then this is a false positive.
4. Integer-only user input: If the tainted input is an integer, or has been sanitized to ensure it is treated as an integer �� for example, sprintf(cmd, "killall process %d", user_input); or int int_var = atoi(user_input); strcpy(buffer, int_var); �� then the external input is strictly a bounded integer with limited length. Such inputs cannot cause a buffer overflow, this is a false positive.
Reporting Guidelines:

If it is not a false positive, reconstruct the required parameter values for triggering the first detected vulnerability based on the analysis.
If a reachable test case is provided in the prompt, use that reachable test case as the base input packet and complete or correct only the required fields so the final PoC still reaches the source point and triggers the sink.
This is the PoC generation stage. The previous stage only determines whether alerts exist, so generate the PoC packet here only after confirming the alert is real.
Format: [('vuln', source_addr, sink_addr), ...] 
POC: {"api_url": ..., "method": ..., "post_payload": {...}}. 
If it is a false positive, return [].

"""
        else:
            self.validation = """
Looking at the above analysis, carefully determine whether the detected alerts represent real command injection vulnerabilities or false positives. Consider the following false positive scenarios:
1. Integer-only user input: If the tainted input affecting the command is a numeric value (e.g., `sprintf(cmd, "killall process %d", user_input); system(cmd);`), where user_input is only an integer and does not allow command injection via shell metacharacters, then it is a false positive.
2. Data from controlled system files: If the tainted input is read from a system-configured or static file with a predefined format (e.g., `fgets(buf, 32, fopen("/etc/config", "r")); system(buf);`), and the file contents cannot be influenced by an attacker, then it is a false positive.
3. Proper sanitization or escaping: If the input is sanitized (e.g., through `escape_shell_cmd()`, `strcspn(input, "&;|")`, or similar filtering mechanisms) before being passed to `system()`, `popen()`, or other command execution functions, then it is a false positive.
Reporting Guidelines:

If it is not a false positive, reconstruct the required parameter values for triggering the first detected vulnerability based on the analysis.
If a reachable test case is provided in the prompt, use that reachable test case as the base input packet and complete or correct only the necessary fields so the PoC remains valid while preserving reachability to the source point.
This is the PoC generation stage. The previous stage only determines whether alerts exist, so generate the PoC packet here only after confirming the alert is real.
Format: 
[('vuln', source_addr, sink_addr), ...] 
POC: {"api_url": ..., "method": ..., "post_payload": {...}}. 
If it is a false positive, return [].
"""
#Think step by step, returns alerts that are not false positives. Return format is [('vuln', {source_addr}, sink_addr)...], otherwise, return an empty list.
    
    def clean_and_parse_json(self, response):
        # clean Markdown
        json_string = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_string:
            json_string = json_string.group(1)
        else:
            json_string = response
        return json_string
     
    def extract_alert_from_content(self, content):
        matches = re.search(r"\('alert',\s*('0x[0-9a-fA-F]+'|\"0x[0-9a-fA-F]+\"|'[^']+'|0x[0-9a-fA-F]+),\s*('0x[0-9a-fA-F]+'\"0x[0-9a-fA-F]+\"|'[^']+'|0x[0-9a-fA-F]+)\)", content)
        if matches:
            return True
        else:
            return False
        
    def extract_unknown_functions(self, llm_output):
        try:
            data = json.loads(llm_output)
            return data.get("Unknown Function", [])
        except json.JSONDecodeError:
            return []
        # pattern = r'"Unknown Function":\s*\[(.*?)\]'
        # match = re.search(pattern, llm_output)
        # if match:
        #     functions_str = match.group(1)
        #     functions = re.findall(r'"([^"]+)"', functions_str)
        #     return functions
        
        
    def send_prompt(self, messages, response_format=None):
        payload = {
            "model": self.model,
            "messages": messages
        }
        if response_format:
            payload["response_format"] = response_format
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {self.api_key}"
        }
        max_retries = 5
        retry_delay = 1
        for attempt in range(max_retries):
            try:
                response = requests.post(self.model_url, headers=headers, json=payload)
                response.raise_for_status()
                # token += response.json()['usage']['total_tokens']
                COT = response.json().get("choices", [{}])[0].get("message", {}).get("reasoning_content", "")
                self.logger.debug(f"COT result\n{COT}\n\n")
                return response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)

        self.logger.debug("Max retries reached without successful response")
        return None
    
    def taint_agent(self, prompt, prompt_count):

        system_message = {
            "role":"system",
            "content":self.taint_content
        }
        user_message = {
            "role": "user",
            "content": prompt
        }
        self.logger.debug(f"taint analysis prompt:\n{prompt}\n\n")
        messages = [system_message, user_message]
        response = self.send_prompt(messages) 
        self.logger.debug(f"taint analysis result:\n{response}\n\n")
        assistant_message = {
            "role": "assistant",
            "content": response,
        }
        messages.append(assistant_message)
        
        # unknown_func = self.extract_unknown_functions(response)
        # if unknown_func:
        #     unknown_func_str = ' '.join(unknown_func)
        #     subprocess.run(['idat', "-A", "-Lida.log", f"-SGet_decompile.py {unknown_func_str}", f'{self.binary}.i64'], check=True)
        #     with open(f'{self.binary_dir}/Unknown_Func.txt', 'r') as file:
        #         unknown_prompt = file.read()
        #     messages.append({"role":"user", "content":unknown_prompt})
        #     self.logger.debug(f"unknown function prompt:\n{unknown_prompt}\n\n")
        #     prompt_count+=1
        #     response = self.send_prompt(messages) 
        #     self.logger.debug(f"unknown function analysis result:\n{response}\n\n")
        #     assistant_message = {
        #         "role": "assistant",
        #         "content": response
        #     }
        #     messages.append(assistant_message)
            
        alert = self.extract_alert_from_content(response)
        # self_validation
        if alert:
            self_validation_prompt = self.validation
            self.logger.debug(f"self_validation prompt:\n{self_validation_prompt}\n")
            
            messages.append({"role": "user", "content": self_validation_prompt})
            prompt_count+=1
            response = self.send_prompt(messages)
            self.logger.debug(f"vuln analysis result:\n{response}\n")
            return response
    

    def dataflow_agent(self, prompt):
        print("None")

    def cross_dataflow_agent(self, prompt):
        print("None")

    def middle_dataflow_agent(self, prompt):
        print("None")

    def crossfunc_taint_agent(self, prompt):
        print("None") 