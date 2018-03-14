from Global import *


# load the line numbers for secure and normal functions
# input: all function names and the corresponding status in all_functions
# output: appended line numbers and the corresponding line status in all_functions
def TZm_load_functions_line_nums():
    for function in all_functions:
        function_name = function[0]
        function_status = function[1]
        line_numbers = extract_function_line_nums(function_status, function_name)
        function.append(copy.deepcopy(line_numbers))
    # swei: trim functions that do not have line numbers (e.g., functions from built-in math libraries)
    all_functions[:] = [function for function in all_functions if len(function[2]) !=0]


# extract function line numbers
# input: the function type and the function name
# output: function_line_nums -> [[line_num, line_status], ...]
def extract_function_line_nums(function_type, function_name):
    found_function = False
    stack = []
    function_line_nums = []
    line_num_list = []
    line_num = 0
    file = open(source_file)
    for line in file:
        line_num += 1
        # find the function name
        token = line.strip().split(" ")
        if len(token) > 1:
            token = token[1].split("(")
            if len(token) > 1:
                potential_function = token[0]
                # checking to see if the function name matches the one we are looking for
                if potential_function == function_name:
                    found_function = True
                    token = line.strip().split(" ")
                    token = token[len(token)-1]
                    # checking to see if the { is in the function signature
                    if ( token.endswith("{")):
                        line_num_list.append(line_num)
                        line_num_list.append(function_type)
                        function_line_nums.append(copy.deepcopy(line_num_list))
                        line_num_list.clear()
                        stack.append("{")
                        continue
        if found_function and stack:
            line_num_list.append(line_num)
            line_num_list.append(function_type)
            function_line_nums.append(copy.deepcopy(line_num_list))
            line_num_list.clear()
            if line.strip().endswith("{") or line.strip() == "{":
                stack.append("{")
            if line.strip().startswith("}") or line.strip() == "{":
                stack.pop()
    return function_line_nums