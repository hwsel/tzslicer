import sys
import copy
import linecache

# sys.argv[1] is the file name
# sys.argv[2]-sys.argv[3]
# 0-0: TZ-M
# 1-0: TZ-B
# 1-1: TZ-L
# sys.argv[4] indicates unrolling
# sys.argv[5] indicates reordering

taintAnalysis_log = sys.argv[1] + "/" + sys.argv[1] + ".txt"
taintAnalysis_content = []

source_file = sys.argv[1] + "/" + sys.argv[1] + ".c"

secure_functions_content = []
normal_functions_content = []

all_functions = []

secure_globals = []
normal_globals = []
secure_main = []
normal_main = []

secure_subfunction_main = []
subfunction_in_secureMain = [] # parentFunction_index, subfunctionCall_lineNum, argument_type, argument_name

all_secure_shared_data = []
all_normal_shared_data = []

# loop_remainder = []

# write the contents of the taintgrind log to a global list called taintAnalysis_content
# input: taintAnalysis_log
# output: taintAnalysis_content
def read_taintAnalysis_log():
    # retrieve the contents from the file and place it in the global list called taintAnalysis_content
    file = open(taintAnalysis_log)
    for line in file:
        taintAnalysis_content.append(line.strip())


# determines if the function belongs in the secure world or normal world
# input: taintAnalysis_content
# output: all_functions -> [[function_name, function_status], ...]
def determine_functions():
    for line in taintAnalysis_content:
        # splitting by pipe
        split_pipe = line.split("|")
        # find tainted instructions
        if len(split_pipe) > 4:
            # ignore blank spaces
            function_name = split_pipe[0].split(" ")[1]
            # add the function name into all_functions
            function_index = 0
            for function in all_functions:
                if function[0] == function_name:
                    break
                function_index += 1
            if function_index == len(all_functions):
                all_functions.append(copy.deepcopy([function_name]))
            if split_pipe[4] != '':
                # main function is probably tainted, but it should still reside in the normal world
                if function_name != "main":
                    # add the function name to the list, without adding duplicates
                    if [function_name] in all_functions:
                        # add the function status into all_functions
                        all_functions[all_functions.index([function_name])].append('s')

    # append the status for the normal functions in all_functions
    function_index = 0
    for function in all_functions:
        if len(function) == 1:
            all_functions[function_index].append('n')
            function_name = function[0]
        function_index += 1


# extract the line range for if-else statement
# input: all_functions -> [[function_name, function_status, [[line_num, line_status], ...]], ...]
# output: all_functions -> [[function_name, function_status, [[line_num, line_status], ...],
# [[if_head, if_tail, else_head, else_tail], ...]], ...]
def extract_if_else_statements():
    for function in all_functions:
        line_numbers = function[2]
        # extract the line range for if statements
        if_statements = extract_if_else_line_range('if', line_numbers)
        function.append(if_statements)
        # extract the line range for else statements
        else_statements = extract_if_else_line_range('else', line_numbers)
        for else_state in else_statements:
            else_head = else_state[0]
            else_tail = else_state[1]
            for if_state in if_statements:
                if_tail = if_state[1]
                if (if_tail + 1) == else_head:
                    if_state.append(else_head)
                    if_state.append(else_tail)


# extract the line range for if or else statements
# input: extract_type (if or else), function_line_nums
# output: conditional statement line ranges
def extract_if_else_line_range(extract_type, function_line_nums):
    if_else_statements = []
    condition_statements = []
    bracket_count_list = []
    for line_num_list in function_line_nums:
        line_num = line_num_list[0]
        if linecache.getline(source_file, line_num).find(extract_type) != -1:
            condition_statements.append(line_num)
            if len(bracket_count_list) >= 1:
                for i in range(0, len(bracket_count_list)):
                    bracket_count_list[i] += 1
            bracket_count_list.append(1)
        else:
            if linecache.getline(source_file, line_num).find('{') != -1:
                if len(bracket_count_list) >= 1:
                    for i in range(0, len(bracket_count_list)):
                        bracket_count_list[i] += 1
            elif linecache.getline(source_file, line_num).find('}') != -1:
                if len(bracket_count_list) >= 1:
                    bracket_count_index = 0
                    while (1):
                        bracket_count_list[bracket_count_index] -= 1
                        if bracket_count_list[bracket_count_index] == 0:
                            current_statement = []
                            current_statement.append(condition_statements[-1])
                            current_statement.append(line_num)
                            if_else_statements.append(current_statement)
                            del condition_statements[-1]
                            del bracket_count_list[bracket_count_index]
                        else:
                            bracket_count_index += 1
                        if bracket_count_index == len(bracket_count_list):
                            break
    return if_else_statements


# extract the line range for loop statements
# input: all_functions -> [[function_name, function_status, [[line_num, line_status], ...], [[if_head, if_tail, else_head, else_tail], ...]], ...]
# output: all_functions -> [[function_name, function_status, [[line_num, line_status], ...],
# [[if_head, if_tail, else_head, else_tail], ...], [[loop_head, loop_tail], ...]], ...]
def extract_loop_statements():
    for function in all_functions:
        line_numbers = function[2]
        loop_statements = extract_loop_line_range(line_numbers)
        function.append(copy.deepcopy(loop_statements))


# extract the line range for if or else statements
# input: function_line_nums
# output: line ranges for loop statements
def extract_loop_line_range(function_line_nums):
    loop_statements = []
    statements = []
    bracket_count_list = []
    for line_num_list in function_line_nums:
        line_num = line_num_list[0]
        if linecache.getline(source_file, line_num).find('for') != -1 or linecache.getline(source_file, line_num).find('while') != -1:
            statements.append(line_num)
            if len(bracket_count_list) >= 1:
                for i in range(0, len(bracket_count_list)):
                    bracket_count_list[i] += 1
            bracket_count_list.append(1)
        else:
            if linecache.getline(source_file, line_num).find('{') != -1:
                if len(bracket_count_list) >= 1:
                    for i in range(0, len(bracket_count_list)):
                        bracket_count_list[i] += 1
            elif linecache.getline(source_file, line_num).find('}') != -1:
                if len(bracket_count_list) >= 1:
                    bracket_count_index = 0
                    while (1):
                        bracket_count_list[bracket_count_index] -= 1
                        if bracket_count_list[bracket_count_index] == 0:
                            current_statement = []
                            current_statement.append(statements[-1])
                            current_statement.append(line_num)
                            loop_statements.append(current_statement)
                            del statements[-1]
                            del bracket_count_list[bracket_count_index]
                        else:
                            bracket_count_index += 1
                        if bracket_count_index == len(bracket_count_list):
                            break
    return loop_statements


# extract the arguments and variables in the function
# input: all_functions -> [[function_name, function_status, [[line_num, line_status], ...], [[if_head, if_tail, else_head, else_tail], ...], [[loop_head, loop_tail], ...]], ...]
# output: all_functions -> [[function_name, function_status, [[line_num, line_status], ...],
# [[if_head, if_tail, else_head, else_tail], ...], [[loop_head, loop_tail], ...],
# [[[original_arg_type, original_arg_name], ...]], [[original_var_type, original_var_name], ...]], ...]
def extract_arguments_variables_subfunctions():
    function_index = 0
    for function in all_functions:
        function_head = function[2][0][0]
        function_tail = function[2][-1][0]

        # append empty list for the arguments and variables
        function.append([])
        function.append([])
        # append empty list for the subfunction_call in all_function
        function.append([])

        # add arguments into all_functions
        original_arg = []
        function_definition = linecache.getline(source_file, function_head)[linecache.getline(source_file, function_head).find('(')+1:linecache.getline(source_file, function_head).find(')')].split(', ')
        for argument_list in function_definition:
            argument = [argument_list.split(' ')[0]]
            argument.append(argument_list.split(' ')[1])
            original_arg.append(argument)
        function[5].append(original_arg)

        # add variables into all_functions
        original_var = []
        for line_index in range(function_head+1,function_tail):
            current_line_list = linecache.getline(source_file, line_index).strip().split(' ')
            if current_line_list[0] == 'int' or current_line_list[0] == 'double' or current_line_list[0] == 'char':
                variable = [current_line_list[0]]
                variable.append(current_line_list[1].split(';')[0])
                original_var.append(variable)

            # add subfunction call into all_functions
            append_subfunction_call(function_index, current_line_list, line_index)

        function[6].append(original_var)
        function_index += 1
    # print('TZm: ', all_functions)


# add subfunction call into all_functions
# input: function_index, line_list, line_num
# output: update subfunction_call list
def append_subfunction_call(function_index, line_list, line_num):
    for line_element in line_list:
        subfunction_index = check_subfunction_call(line_element)
        if subfunction_index != -1:
            subfunction_name = all_functions[subfunction_index][0]
            subfunction_append_index = extract_subfunction_list_index(function_index, subfunction_name)
            if subfunction_append_index == -1:
                all_functions[function_index][7].append([subfunction_name])
                all_functions[function_index][7][-1].append([line_num])
                all_functions[function_index][7][-1].append([extract_subfunction_arguments(line_element)])
            else:
                all_functions[function_index][7][subfunction_append_index][1].append(line_num)
                all_functions[function_index][7][subfunction_append_index][2].append(extract_subfunction_arguments(line_element))


# check if there is a subfunction call in the line element (the line element is splited by space in a certain line)
# input: line_element
# output: -1: not a subfunction call; otherwise, return function index in all_functions
def check_subfunction_call(line_element):
    function_index = 0
    for function in all_functions:
        function_name = function[0]
        if line_element.find(function_name) != -1:
            return function_index
        function_index += 1
    return -1


# check if the subfunction exists in the subfunction_call list already
# input: function_index, subfunction_index
# output: True: exist; False: does NOT exist
def check_if_subfunction_exist(function_index, subfunction_index):
    subfunction_call = all_functions[function_index][7]
    subfunction_name = all_functions[subfunction_index][0]
    for subfunction_list in subfunction_call:
        current_subfunction_name = subfunction_list[0]
        if current_subfunction_name == subfunction_name:
            return True
    return False


# obtain the called arguments for the certain subfunction
# input: subfunction_call
# output: argument list
def extract_subfunction_arguments(subfunction_call):
    arguments = []
    called_arguments = subfunction_call[subfunction_call.find('(')+1:subfunction_call.find(')')].split(',')
    for called_arg in called_arguments:
        arguments.append(called_arg)
    return arguments


# extract the subfunction index in subfunction_call list
# input: function_index, subfunction_name
# output: the index in subfunction_call list for the certain subfunction
def extract_subfunction_list_index(function_index, subfunction_name):
    subfunction_call = all_functions[function_index][7]
    subfunction_list_index = 0
    for subfunction_list in subfunction_call:
        current_subfunction_name = subfunction_list[0]
        if current_subfunction_name == subfunction_name:
            return subfunction_list_index
        subfunction_list_index += 1
    return -1


def shared_data_statement(name_list, type_list, line_num):
    types = ''
    names = ''
    # print(name_list)
    for type in type_list:
        types += ('"' + type + '",')
    for name in name_list:
        names += (name + ',')
    return ('void *' + 'sharedData_' + line_num + '[] = {' + names[:-1] + '};\n') \
           + ('char *' + 'sharedType_' + line_num + '[] = {' + types[:-1] + '};\n') \
           + ('push(' + 'sharedData_' + line_num + ',' + 'sharedType_' + line_num + ');\n')

def subfunction_call_content(parentFunction_index, name_list, type_list, line_num):
    define_statements = ''
    for name in name_list:
        parent_line_list_index = 0
        for parent_line_list in all_functions[parentFunction_index][2]:
            parent_line_num = parent_line_list[0]
            parent_line_content = linecache.getline(source_file, parent_line_num)
            if parent_line_content.find(name) != -1:
                if parent_line_list_index == 0:
                    argument_define = parent_line_content.strip()[parent_line_content.find('(')+1:parent_line_content.find(')')]
                    print('testing needed when the defining statement is in the function argument definition')
                else:
                    define_statements += parent_line_content
                break
            parent_line_list_index += 1

    types = ''
    names = ''
    for type in type_list:
        types += ('"' + type + '",')
    for name in name_list:
        names += (name + ',')
    return define_statements + ('void *' + 'sharedData_' + line_num + '[] = {' + names[:-1] + '};\n') \
           + ('char *' + 'sharedType_' + line_num + '[] = {' + types[:-1] + '};\n') \
           + ('pull(' + 'sharedData_' + line_num + ',' + 'sharedType_' + line_num + ');\n')



# starts the parsing process
# input: secure_functions_content and normal_functions_content
# output: secure_main, normal_main and main_source
def parse():
    main_source = []
    global secure_functions_content
    global normal_functions_content
    global subfunction_in_secureMain

    secure_functions_content = load_functions('secure')
    final_line_count(secure_functions_content)
    normal_functions_content = load_functions('normal')

    if (sys.argv[2] == '0' and sys.argv[3] == '0') or (sys.argv[2] == '1' and sys.argv[3] == '0'):
        for subfunction in subfunction_in_secureMain:
            parentFunction_index = subfunction[0]
            parentFunction_name = all_functions[parentFunction_index][0]
            for normal_func_content_list in normal_functions_content:
                normal_func_name = normal_func_content_list[0]
                if normal_func_name == parentFunction_name:
                    for line_list in normal_func_content_list[1]:
                        line_num = line_list[1]
                        if int(line_num) in subfunction[1]:
                            index = subfunction[1].index(int(line_num))
                            # update secure_main
                            if sys.argv[2] == '1' and sys.argv[3] == '1':
                                secure_main.append(subfunction_call_content(parentFunction_index, subfunction[2][index], subfunction[3][index], line_num))
                            # secure_main.append(line_list[0])
                            # update normal function content
                            if sys.argv[2] == '1' and sys.argv[3] == '1':
                                line_list[0] = shared_data_statement(subfunction[2][index], subfunction[3][index], line_num) + "\tasm volatile(\"smc #0\\n\\t\");\n"

    # scheduling: renaming
    # check if we need renaming
    if sys.argv[2] == '1' and sys.argv[3] == '1' and sys.argv[4] != '0':
        for function in all_functions:
            function_name = function[0]
            function_status = function[1]
            if function_status == 'b':
                line_numbers = function[2]
                loop_statements = function[4]
                shared_arguments = function[5][4]
                shared_variables = function[6][4]
                for loop_state in loop_statements:
                    rename_var_list = check_renaming_need(loop_state, line_numbers, shared_arguments, shared_variables)
                    if rename_var_list:
                        loop_head = loop_state[0]
                        loop_tail = loop_state[1]
                        loop_head_index = loop_head - line_numbers[0][0]
                        loop_tail_index = loop_tail - line_numbers[0][0]
                        for loop_line_index in range(loop_head_index+1, loop_tail_index):
                            line_num = line_numbers[loop_line_index][0]
                            line_status = line_numbers[loop_line_index][1]
                            line_content = linecache.getline(source_file, line_num)
                            for rename_var in rename_var_list:
                                if line_content.find(rename_var) != -1:
                                    rename_var_in_line(function_name, line_num, line_status, rename_var, sys.argv[4])
                        # append statements for assigning the renamed variable to the orignal variable
                        append_updated_assignment(function_name, line_numbers[loop_tail_index][0], 'n', rename_var_list, sys.argv[4])
                        append_updated_assignment(function_name, line_numbers[loop_tail_index][0], 's', rename_var_list, sys.argv[4])

    for function in normal_functions_content:
        if function[0] == "main":
            # evaluating the main
            previous_flag = False
            for i in range(1, len(function[1])-1, 1):
                line = function[1][i][0]
                is_secure_call = False
                is_normal_call = False
                is_function_call = False
                # removing taint grind annotations
                if line.strip().split("_")[0] != "TNT":
                    # check for the 3 different variations of a function being called
                    function_call = line.split("(")[0].strip()
                    if len(line.split("=")) > 1:
                        function_call = line.split("=")[1].split("(")[0].strip()
                    # seeing if its a secure function or not
                    for secure_function in secure_functions_content:
                        if secure_function[0] == function_call:
                            is_secure_call = True
                            is_function_call = True
                    # seeing if its a normal function or not
                    for normal_function in normal_functions_content:
                        if normal_function[0] == function_call:
                            is_function_call = True
                            is_normal_call = True
                    # if it is a secure function call
                    if is_function_call:
                        if is_secure_call:
                            # add definitions of function arguments
                            if not previous_flag:
                                for previous_line_num in range(1, i, 1):
                                    previous_line = function[1][previous_line_num][0]
                                    if previous_line.strip().split("_")[0] != "TNT" and previous_line_num > 0:
                                        secure_main.append("\t\t%s\n" % previous_line.strip())
                                previous_flag = True
                            # # need to check the arguments of the function
                            # argument_list = line.strip().split("(")[1].split(",")
                            # # removing the ); from the very last argument
                            # last_argument = argument_list[len(argument_list)-1]
                            # last_argument_fixed = last_argument[0:len(last_argument)-2].strip()
                            # # delete the last element from the argument list
                            # del argument_list[-1]
                            # # add the correct version of the argument list back in
                            # argument_list.append(last_argument_fixed)
                            # # now that we have our argument list, time to iterate through them and inserting trustzone code
                            # for variable in variables:
                            #     # since we are only dealing with the main function, find the main function
                            #     if variable[0] == "main":
                            #         # iterating through the function's variables
                            #         for i in range(1,len(variable),1):
                            #             variable_name = variable[i][1]
                            #             variable_type = variable[i][0]
                            #             # now iterating through the argument list to see which ones are being used
                            #             for arguments in argument_list:
                            #                 if variable_name == arguments:
                            #                     # need to see if its a string or not
                            #                     if variable_type == "char" or variable_type == "char*":
                            #                         check_string = len(variable[i])
                            #                         # it is a string, find the size
                            #                         if check_string == 3:
                            #                             size = variable[i][2]
                            #                             # add to main insertion code
                            #                             main_source.append("\tpushString(&%s,%s);\n" % (variable_name,size))
                            #                             # add to secure insertion code
                            #                             # assigning a string to a global variable in the secure world
                            #                             secure_globals.append(("%s %s[%s] = \"\";\n" % (variable_type,variable_name,size)))
                            #                             # adding to secure world insertion
                            #                             secure_main.append("\t\tpullString(%s,%s);\n" % (variable_name,size))
                            #                     elif variable_type == "double":
                            #                         main_source.append("\tpushDouble(&%s);\n" % (variable_name))
                            #                     elif variable_type == "int":
                            #                         main_source.append("\tpushInteger(&%s);\n" % (variable_name))
                            #                         secure_main.append("\t\t%s = pullInteger();\n" % variable_name)
                            #                         secure_main.append("\t\tpullInteger(&%s);\n" % variable_name)
                            # Need to insert the SMC call
                            if not is_normal_call:
                                main_source.append("\tasm volatile(\"smc #0\\n\\t\");\n")
                            # Need to add to the secure world now
                            # call the function in the secure world
                            secure_main.append("\t\t%s\n" % line.strip())
                            secure_main.append("\tasm volatile(\"smc #0\\n\\t\");\n")
                            # check if the function call is only in the secure world or in the both worlds
                            if is_normal_call:
                                main_source.append(line)
                        else:
                            main_source.append(line)
                    else:
                        main_source.append(line)
    for line in main_source:
        normal_main.append(line)



def append_updated_assignment(function_name, loop_tail, line_status, rename_var_list, unrolling_times):
    if line_status == 's':
        functions_content = secure_functions_content
    elif line_status == 'n':
        functions_content = normal_functions_content
    for func_content_list in functions_content:
        current_function_name = func_content_list[0]
        if current_function_name == function_name:
            func_content = func_content_list[1]
            line_content_list_index = 0
            while(1):
                line_content_list = func_content[line_content_list_index]
                line_label = line_content_list[1]
                if line_label.find(str(loop_tail)) != -1:
                    for rename_var in rename_var_list[::-1]: # reversely insert the new assignment for the renamed variable
                        add_line = rename_var + ' = ' + rename_var + '_' + str(int(unrolling_times)-1) + ';\n'
                        added_line_label = rename_var + '_assign'
                        func_content.insert(line_content_list_index, [add_line, added_line_label])
                    break
                line_content_list_index += 1


# rename variable
# input: function_name, line_num, line_status, rename_var
# output: rename the variable in the current line
def rename_var_in_line(function_name, line_num, line_status, rename_var, unrolling_times):
    if line_status == 's':
        functions_content = secure_functions_content
    elif line_status == 'n':
        functions_content = normal_functions_content
    for func_content_list in functions_content:
        current_function_name = func_content_list[0]
        if current_function_name == function_name:
            func_content = func_content_list[1]
            line_content_list_index = 0
            unrolling = 1
            while(1):
                if line_content_list_index == len(func_content):
                    break
                line_content_list = func_content[line_content_list_index]
                line_label = line_content_list[1]
                if line_label.find('_') != -1 and line_label.find(str(line_num)) != -1:
                    line_content = line_content_list[0]
                    if line_content.find(rename_var) != -1:
                        rename_rule = line_label[line_label.find('_'):]
                        rename_var_index_list = find_element_in_line(rename_var, line_content)
                        add_line = ''
                        begin_index = 0
                        equal_index = line_content.find('=')
                        for rename_var_index in rename_var_index_list:
                            # end_index = rename_var_index + len(rename_var)
                            # add_line += line_content[begin_index:end_index] + rename_rule
                            # begin_index = end_index
                            end_index = rename_var_index + len(rename_var)
                            if rename_var_index < equal_index:
                                add_line += line_content[begin_index:end_index] + rename_rule
                            else:
                                if rename_rule == str('_1'):
                                    add_line += line_content[begin_index:end_index]
                                else:
                                    previous_rename_rule = '_' + str(int(rename_rule[1:]) - 1)
                                    add_line += line_content[begin_index:end_index] + previous_rename_rule
                            begin_index = end_index
                        add_line += line_content[end_index:]
                        func_content.insert(line_content_list_index+1, [add_line, line_label])
                        del func_content[line_content_list_index]
                    unrolling += 1
                if unrolling == int(unrolling_times):
                    break
                line_content_list_index += 1

    for unrolling in range(1,int(unrolling_times)):
        rename_rule = '_' + str(unrolling)
        def_line_index,sd_line_index = extract_var_def_sd(func_content, function_name)
        find_var,var,var_type = find_var_type(func_content,rename_var,sd_line_index)
        # Work around here. Haven't dealt with if the variable is not in the shared data list
        if find_var:
            func_content.insert(def_line_index+1, [var_type[var_type.find('\"')+1:-1] + ' ' + rename_var+rename_rule + ';\n', rename_var+rename_rule])
            func_content[sd_line_index+1][0] = func_content[sd_line_index+1][0][:func_content[sd_line_index+1][0].find('}')] + ',' + var+rename_rule + '};\n'
            func_content[sd_line_index+2][0] = func_content[sd_line_index+2][0][:func_content[sd_line_index+2][0].find('}')] + ',' + var_type + '};\n'


# extract the line index of variable definition and the shared data statement
def extract_var_def_sd(func_content, function_name):
    line_index = 1
    for line_content_list in func_content[1:]:
        line_content = line_content_list[0]
        if line_content.find(function_name) != -1:
            return line_index-1,line_index
        line_index += 1


# extract the renamed data type based on the original shared data
def find_var_type(func_content, rename_var, sd_line_index):
    if func_content[sd_line_index][0].find(rename_var) != -1:
        shared_var_list = func_content[sd_line_index][0][func_content[sd_line_index][0].find('{')+1:func_content[sd_line_index][0].find('}')].split(',')
        shared_var_index = 0
        for shared_var in shared_var_list:
            if shared_var.find(rename_var) != -1:
                shared_type_list = func_content[sd_line_index+1][0][func_content[sd_line_index+1][0].find('{')+1:func_content[sd_line_index+1][0].find('}')].split(',')
                return True, shared_var, shared_type_list[shared_var_index]
            shared_var_index += 1


# find the index based on certain content (secure content or normal content)
# input: line_numbers, loop_line_num, line_status
# output: return the corresponding index
# def find_content_index(line_numbers, loop_line_num, line_status):
#     index = -1
#     unrolling_times = 0
#     for line_num_list in line_numbers:
#         current_line_num = line_num_list[0]
#         current_line_status = line_num_list[1]
#         if current_line_status == line_status or current_line_status == 'b':
#             index += 1
#         if len(line_num_list) == 3:
#             unrolling_times += 1
#         if current_line_num == loop_line_num:
#             return index, unrolling_times


# renaming the shared variables
# input: line_status, function_name, rename_var
# output: renaming
def update_line_content_by_renaming(line_status, function_name, rename_var):
    if line_status == 's':
        functions_content = secure_functions_content
    elif line_status == 'n':
        functions_content = normal_functions_content
    for func_content_list in functions_content:
        current_function_name = func_content_list[0]
        if current_function_name == function_name:
            func_content = func_content_list[1]
            line_content_list_index = 0
            while(1):
                if line_content_list_index == len(func_content):
                    break
                line_content_list = func_content[line_content_list_index]
                line_label = line_content_list[1]
                if line_label.find('_') != -1:
                    line_content = line_content_list[0]
                    if line_content.find(rename_var) != -1:
                        rename_rule = line_label[line_label.find('_'):]
                        rename_var_index_list = find_element_in_line(rename_var, line_content)
                        add_line = ''
                        begin_index = 0
                        for rename_var_index in rename_var_index_list:
                            end_index = rename_var_index + len(rename_var)
                            add_line += line_content[begin_index:end_index] + rename_rule
                            begin_index = end_index
                        add_line += line_content[end_index:]
                        func_content.insert(line_content_list_index+1, [add_line, line_label])
                        del func_content[line_content_list_index]
                        break
                line_content_list_index += 1


# check if we need renaming
# input: loop_state, line_numbers, shared_arguments, shared_variables
# output: True: need; False: NOT need
def check_renaming_need(loop_state, line_numbers, shared_arguments, shared_variables):
    loop_head = loop_state[0]
    loop_tail = loop_state[1]
    loop_head_index = loop_head - line_numbers[0][0]
    loop_tail_index = loop_tail - line_numbers[0][0]
    assigned_variable_list = []
    variable_list = []
    if line_numbers[loop_head_index][1] == 'b':
        start_flag = False
        for loop_line_index in range(loop_head_index+1, loop_tail_index):
            line_num = line_numbers[loop_line_index][0]
            line_status = line_numbers[loop_line_index][1]
            line_content = linecache.getline(source_file, line_num)
            if not start_flag:
                if line_status != 'b' and line_status != 'x':
                    if line_status == 'n':
                        start_flag = True
                        if line_content.find(' = ') != -1:
                            assigned_variable = line_content.strip().split(' = ')[0]
                            if assigned_variable.find('[') == -1:
                                if (not find_shared_data(assigned_variable, shared_arguments, shared_variables)) or len(line_numbers[loop_line_index]) == 2:
                                    return False
                                else:
                                    assigned_variable_list.append(assigned_variable)
                            else:
                                return False
                        else:
                            return False
                    else:
                        return False
                elif line_status == 'b' and line_content.find('for') != -1:
                    return False
            else:
                if line_status == 's':
                    if line_content.find(' = ') != -1:
                        assigning_side = line_content.strip().split(' = ')[1]
                        if find_shared_data(assigning_side, shared_arguments, shared_variables):
                            for assigned_variable in assigned_variable_list:
                                if assigning_side.find(assigned_variable) != -1:
                                    if assigned_variable not in variable_list:
                                        variable_list.append(assigned_variable)
                elif line_status == 'n':
                    if line_content.find(' = ') != -1:
                        assigned_variable = line_content.strip().split(' = ')[0]
                        if assigned_variable.find('[') == -1:
                            if find_shared_data(assigned_variable, shared_arguments, shared_variables) and len(line_numbers[loop_line_index]) == 3:
                                assigned_variable_list.append(assigned_variable)
    else:
        return False
    if variable_list:
        return variable_list
    else:
        return False


# check if the variable in the shared list
# input: assigned_variable, shared_arguments, shared_variables
# output: True: is shared data; False: is NOT shared data
def find_shared_data(content, shared_arguments, shared_variables):
    if list_element_find(content, shared_arguments) or list_element_find(content, shared_variables):
        return True
    else:
        return False


# check if the variable is in the list
# input: variable, list
# output: True: in list; False: NOT in list
def list_element_find(content, list):
    for var_list in list:
        var_name = var_list[1]
        if content.find(var_name) != -1:
            return True
    return False


# extract the content of functions
# input: function_type ('secure' or 'normal')
# output: functions_content
def load_functions(function_type):
    functions_content = []
    if function_type == 'secure':
        function_status = 's'
    elif function_type == 'normal':
        function_status = 'n'
    function_index = 0
    global shared_data
    for function in all_functions:
        current_function_status = function[1]
        if current_function_status == function_status or current_function_status == 'b':
            function_name = function[0]
            function_content = [function_name]
            function_content.append(copy.deepcopy(read_function_content(function_index, function_status)))
            functions_content.append(function_content)
        function_index += 1
    return functions_content


# append statements for pulling/pushing shared arguments and variables
# input: shared_arg_var
# output: appending statements
def append_shared_arg_var_multi_statements(statements_type, shared_arg_var):
    statements = ''
    for arg_var_list in shared_arg_var:
        type = arg_var_list[0]
        name = arg_var_list[1]
        if type == 'int':
            if name.find('[') != -1:
                statements = statements + statements_type + 'Integer(' + name[:name.find('[')] + ')' + '; '
            elif name.find('*') != -1:
                statements = statements + statements_type + 'Integer(' + name[1:] + ')' + '; '
            else:
                statements = statements + statements_type + 'Integer(' + '&' + name + ')' + '; '
        elif type == 'double':
            if name.find('[') != -1:
                statements = statements + statements_type + 'Double(' + name[:name.find('[')] + ')' + '; '
            elif name.find('*') != -1:
                statements = statements + statements_type + 'Double(' + name[1:] + ')' + '; '
            else:
                statements = statements + statements_type + 'Double(' + '&' + name + ')' + '; '
    return statements


# obtain the push/pull statements
# input: obtain
# output: pull/push statements
def push_pull_multi_statements(statements_type, function_index):
    shared_arg = all_functions[function_index][5][4]
    shared_var = all_functions[function_index][6][4]
    statements = ''
    if shared_arg:
        statements = statements + append_shared_arg_var_multi_statements(statements_type, shared_arg)
    if shared_var:
        statements = statements + append_shared_arg_var_multi_statements(statements_type, shared_var)
    return statements


# check if the line is the loop statement
def loop_check(line_num):
    line_content = linecache.getline(source_file, line_num)
    if line_content.find('while') != -1 or line_content.find('for') != -1:
        return True
    return False


# check if the line is the if-else statement
def if_check(line_num):
    line_content = linecache.getline(source_file, line_num)
    if line_content.find('if') != -1 or line_content.find('else') != -1:
        return True
    return False


# extract the data address
# input: shared_arg_name
# output: data address + ','
def extract_data_address_type(shared_list):
    # print('!!!!!!')
    shared_type = shared_list[0]
    shared_name = shared_list[1]
    if shared_name.find('*') != -1:
        return '"' + shared_type + '"' + ',', shared_name[1:] + ','
        # return '"' + shared_type + '"' + ',', shared_name + ','
    elif shared_name.find('[') != -1:
        # return '"' + shared_type + '"' + ',', shared_name[:shared_name.find('[')] + ','
        # return '"' + shared_type + '"' + ',' + '_' + shared_name[shared_name.find['[']+1:shared_name.find[']']], shared_name[:shared_name.find('[')] + ','
        # return '"' + shared_type + '"' + ',' + '*' + shared_name[shared_name.find['[']+1:shared_name.find[']']], shared_name[:shared_name.find('[')] + ','
        return '"' + shared_type + '"' + ',', shared_name[:shared_name.find('[')] + '+' + shared_name[shared_name.find('[')+1:shared_name.find(']')] + ','
    else:
        return '"' + shared_type + '"' + ',', '&' + shared_name + ','
        # return '"' + shared_type + '"' + ',', shared_name + ','


# read the line status data structure and write into the list
# input: function_index in all_functions, function_status
# output: function_content
def read_function_content(function_index, function_status):
    global all_secure_shared_data
    global all_normal_shared_data
    function_name = all_functions[function_index][0]
    if function_status == 's':
        opposite_status = 'n'
    elif function_status == 'n':
        opposite_status = 's'
    function_content = []
    head_flag = False
    line_num_list_index = 0
    unrolling_flag = False
    variable_definition_flag = False
    shared_multi_type = '{'
    shared_multi_data = '{'
    # if len(all_functions[function_index][5]) >= 4:
    #     shared_data = all_functions[function_index][5][4]
    # if len(all_functions[function_index][6]) >= 4:
    #     shared_data += all_functions[function_index][6][4]
    if len(all_functions[function_index][5]) >= 4:
        for shared_arg_list in all_functions[function_index][5][4]:
            shared_type, shared_data = extract_data_address_type(shared_arg_list)
            shared_multi_type += shared_type
            shared_multi_data += shared_data
    if len(all_functions[function_index][6]) >= 4:
        for shared_var_list in all_functions[function_index][6][4]:
            shared_type, shared_data = extract_data_address_type(shared_var_list)
            shared_multi_type += shared_type
            shared_multi_data += shared_data
    shared_multi_type = shared_multi_type[:-1]
    shared_multi_type += '}'
    shared_multi_data = shared_multi_data[:-1]
    shared_multi_data += '}'
    if function_status == 's':
        if shared_multi_data != '}':
            all_secure_shared_data.append([function_name,[shared_multi_type],[shared_multi_data]])
    elif function_status == 'n':
        if shared_multi_data != '}':
            all_normal_shared_data.append([function_name,[shared_multi_type], [shared_multi_data]])
    loop_if_flag = False
    while(1):
        if line_num_list_index == len(all_functions[function_index][2]):
            break
        line_num_list = all_functions[function_index][2][line_num_list_index]
        current_line_status = line_num_list[1]
        if not head_flag:
            if current_line_status == 'b' or current_line_status == 'x':
                previous_line_status = function_status
            else:
                previous_line_status = current_line_status
            head_flag = True
        else:
            # if line_num_list[0] >= 67 and line_num_list[0] <= 87:
            #     print(line_num_list,previous_line_status,current_line_status,opposite_status)
            # Testing Needed !!!!
            if (previous_line_status == function_status and current_line_status == opposite_status):
                if function_status == 'n' and (shared_multi_data != '}' or loop_if_flag):
                    # push_statement = 'push(' + function_name + '_sharedData,' + function_name + '_sharedType);'
                    # if push_statement:
                    # function_content.append(['\t'+push_statement+'\n', 'push'])
                    push_smc_statement = 'push_smc(' + function_name + '_sharedData,' + function_name + '_sharedType,' + 'sizeof(' +function_name + '_sharedData)/sizeof(*' +function_name + '_sharedData)' + ');'
                    function_content.append(['\t'+push_smc_statement+'\n', 'push_smc'])
                # function_content.append(["\tasm volatile(\"smc #0\\n\\t\");\n", 'smc'])
                # add push pull
                if function_status == 's' and shared_multi_data != '}':
                    # pull_statement = 'pull(' + function_name + '_sharedData,' + function_name + '_sharedType);'
                    # if pull_statement:
                    # function_content.append(['\t'+pull_statement+'\n', 'pull'])
                    smc_pull_statement = 'smc_pull(' + function_name + '_sharedData,' + function_name + '_sharedType,' + 'sizeof(' +function_name + '_sharedData)/sizeof(*' +function_name + '_sharedData)' + ');'
                    function_content.append(['\t'+smc_pull_statement+'\n', 'smc_pull'])
            loop_if_flag = False
            if current_line_status != 'b' and current_line_status != 'x':
                previous_line_status = current_line_status
            elif current_line_status == 'b':
                previous_line_status = function_status
                if loop_check(line_num_list[0]) or if_check(line_num_list[0]):
                    loop_if_flag = True
        line_num = line_num_list[0]
        if current_line_status == function_status or current_line_status == 'b':
            if (not variable_definition_flag) and (not is_var_definition(linecache.getline(source_file, line_num))):
                variable_definition_flag = True
                # or (function_content[0][-1][1] == 'smc' or function_content[0][-1][1] == 'pull' or function_content[0][-1][1] == 'push')
                if sharedDataArray_statement(function_status, function_name):
                    if function_content[-1][1] == 'smc' or function_content[-1][1] == 'smc_pull' or function_content[-1][1] == 'push_smc':
                        if function_content[-1][1] == 'smc_pull':
                            function_content[-1][0] = function_content[-1][0][5:]
                        function_content.insert(-1, [sharedDataArray_statement(function_status, function_name)[0], 'sharedDataArray'])
                        function_content.insert(-1, [sharedDataArray_statement(function_status, function_name)[1], 'sharedTypeArray'])
                    else:
                        function_content.append([sharedDataArray_statement(function_status, function_name)[0], 'sharedDataArray'])
                        function_content.append([sharedDataArray_statement(function_status, function_name)[1], 'sharedTypeArray'])
            function_content.append([linecache.getline(source_file, line_num), str(line_num)])
            # Testing Needed!!!!!! For unrolling and renaming
            if sys.argv[2] == '1' and sys.argv[3] == '1' and sys.argv[4] != '0':
                if not unrolling_flag:
                    unrolling_tail_index = need_unrolling_loop(function_index, line_num_list_index)
                    if unrolling_tail_index != -1:
                        unrolling_flag = True
                        unrolling_times = int(sys.argv[4])
                        loop_remainder = []
                        # if [all_functions[function_index][2][line_num_list_index][0],unrolling_tail_index] not in loop_remainder:
                        loop_remainder.append(all_functions[function_index][2][line_num_list_index][0])
                        loop_remainder.append(unrolling_tail_index)
                        iterator,unrolling_loop_definition,adder,operator = loop_iterator_and_definition(function_index, line_num_list_index, str(unrolling_times))
                        del function_content[-1]
                        function_content.append([unrolling_loop_definition, str(line_num)])
                else:
                    line_content = linecache.getline(source_file, line_num)
                    if line_content.find('['+iterator+']') != -1:
                        for add_index in range(1, unrolling_times):
                            iterator_index_list = find_element_in_line('['+iterator+']', line_content)
                            begin_index = 0
                            add_line = ''
                            for iterator_index_element in iterator_index_list:
                                end_index = iterator_index_element + len(iterator) + 1
                                if add_index == 1:
                                    add_line += line_content[begin_index:end_index] + operator + adder
                                else:
                                    add_line += line_content[begin_index:end_index] + operator + adder + '*' + str(add_index)
                                begin_index = end_index
                            add_line += line_content[end_index:]
                            function_content.append([add_line, str(line_num)+'_'+str(add_index)])
                        line_num_list.append(unrolling_times)
                    else:
                        if search_line_status(function_index, line_num) != 'b' and \
                                        line_content.find('while') == -1 and line_content.find('for') == -1 and \
                                        line_content.find('if') == -1 and line_content.find('}') == -1:
                            for add_index in range(1, unrolling_times):
                                if line_content.find(iterator) != -1:
                                    iterator_index_list = find_element_in_line(iterator, line_content)
                                    begin_index = 0
                                    add_line = ''
                                    for iterator_index_element in iterator_index_list:
                                        end_index = iterator_index_element
                                        if add_index == 1:
                                            add_line += line_content[begin_index:end_index] + '(' + iterator + operator + adder + ')'
                                        else:
                                            add_line += line_content[begin_index:end_index] + '(' + iterator + operator + adder + '*' + str(add_index) + ')'
                                        begin_index = end_index
                                    add_line += line_content[end_index+len(iterator):]
                                    function_content.append([add_line, str(line_num)+'_'+str(add_index)])
                                else:
                                    function_content.append([line_content, str(line_num)+'_'+str(add_index)])
                            line_num_list.append(unrolling_times)
                        else:
                            if line_content.find('while') != -1 or line_content.find('for') != -1:
                                loop_end = extract_loop_tail(function_index, line_num)
                                for line_index in range(line_num_list_index+1,loop_end+1):
                                    function_content.append([linecache.getline(source_file, all_functions[function_index][2][line_index][0]), str(all_functions[function_index][2][line_index][0])])
                                line_num_list_index = line_index
            # if sys.argv[2] == '1' and sys.argv[3] == '1' and sys.argv[4] != '0':
                if line_num >= unrolling_tail_index:
                    unrolling_flag = False
                    if unrolling_tail_index != -1:
                        remainder_head = False
                        # for remainder_line in range(int(loop_remainder[0]),int(int(loop_remainder[1])+1)):
                        # remainder_line = int(loop_remainder[0])
                        # while(1):
                        #     if remainder_line == int(int(loop_remainder[1])+1):
                        #         break
                        #     # print(remainder_line)
                        #     if not remainder_head:
                        #         remainder_head = True
                        #         function_content.append([update_remainder(linecache.getline(source_file,remainder_line)), 'loop_remainder'])
                        #     else:
                        #         if line_status_check(remainder_line,function_index,function_status):
                        #             function_content.append([linecache.getline(source_file,remainder_line), 'loop_remainder'])
                        #     remainder_line += 1
                        remainder_line_begin = int(loop_remainder[0])
                        remainder_line_end = int(loop_remainder[1])
                        line_content_list_index = 0
                        # Testing needed!!!!!!
                        remainder_line_begin_index = -1
                        remainder_line_end_index = -1
                        for line_content_list in function_content:
                            line_num_label = line_content_list[1]
                            if line_num_label.isdigit():
                                if int(line_num_label) == remainder_line_begin:
                                    remainder_line_begin_index = line_content_list_index
                                if int(line_num_label) == remainder_line_end:
                                    remainder_line_end_index = line_content_list_index
                                if int(line_num_label) >= remainder_line_begin and int(line_num_label) <= remainder_line_end:
                                    if int(line_num_label) == remainder_line_begin:
                                        loop_remainder_statement = linecache.getline(source_file,int(line_num_label))[:linecache.getline(source_file,int(line_num_label)).find('(')+1] + \
                                            linecache.getline(source_file,int(line_num_label))[linecache.getline(source_file,int(line_num_label)).find(';'):]
                                        function_content.append([loop_remainder_statement, 'loop_remainder_'+line_num_label])
                                    else:
                                        function_content.append([linecache.getline(source_file,int(line_num_label)), 'loop_remainder_'+line_num_label])
                            else:
                                if line_num_label.find('smc') != -1:
                                    if remainder_line_end_index != -1:
                                        break
                                    if remainder_line_begin_index != -1:
                                        function_content.append([line_content_list[0], 'loop_remainder_'+line_num_label])
                            line_content_list_index += 1

            if loop_add_missing_smc(function_index, line_num_list_index, function_status, opposite_status):
                function_content.append(["\tasm volatile(\"smc #0\\n\\t\");\n", 'smc'])
        line_num_list_index += 1
    return function_content


# check if the line status is equal to the function status or not
# output: True - equal, False - not equal
def line_status_check(remainder_line,function_index,function_status):
    line_numbers = all_functions[function_index][2]
    for line_num_list in line_numbers:
        line_num = line_num_list[0]
        if remainder_line == line_num:
            line_status = line_num_list[1]
            if line_status == function_status:
                return True
            elif function_status == 'n' and line_status.find('push_smc') != -1:
                return True
            elif function_status == 's' and line_status.find('smc_pull') != -1:
                return True
            else:
                return False


# update the remainder loop definition
# input: original loop definition
# output: updated remainder loop definition
def update_remainder(line_content):
    unrolling_times = sys.argv[4]
    loop_control_list = line_content[line_content.find('(')+1:line_content.find(')')].split('; ')
    iterator = loop_control_list[0].split(' = ')[0].strip()
    if line_content.find('++') != -1:
        loop_definition = line_content[:line_content.find('++') - len(iterator+'; ')] + '%' + unrolling_times + line_content[line_content.find('++') - len(iterator+'; '):]
    elif line_content.find(' += ') != -1:
        loop_definition = line_content[:line_content.find(' +=') - len(iterator+'; ')] + '%' + unrolling_times + line_content[line_content.find(' +=') - len(iterator+'; '):]
    elif line_content.find('--') != -1:
        loop_definition = line_content[:line_content.find('--') - len(iterator+'; ')] + '%' + unrolling_times + line_content[line_content.find('--') - len(iterator+'; '):]
    elif line_content.find(' -= ') != -1:
        loop_definition = line_content[:line_content.find(' -=') - len(iterator+'; ')] + '%' + unrolling_times + line_content[line_content.find(' -=') - len(iterator+'; '):]
    return loop_definition


# extract the loop tail
# input: function_index, line_num
# output: loop_tail
def extract_loop_tail(function_index, line_num):
    loop_statements = all_functions[function_index][4]
    function_head = all_functions[function_index][2][0][0]
    for loop_state in loop_statements:
        loop_head = loop_state[0]
        if loop_head == line_num:
            loop_tail = loop_state[1]
            loop_tail_index = loop_tail - function_head
            return loop_tail_index


# check if this is a loop and needs unrolling
# ====Alternative==== here we only unroll the last level of loop
# input: function_index, line_num_list_index
# output: -1: keep the same; otherwise: unrolling needed and return the line number of the loop tail
def need_unrolling_loop(function_index, line_num_list_index):
    current_line_list = all_functions[function_index][2][line_num_list_index]
    current_line_num = current_line_list[0]
    current_line_status = current_line_list[1]
    loop_statements = all_functions[function_index][4]
    for loop_state in loop_statements:
        loop_head = loop_state[0]
        if current_line_num == loop_head and current_line_status == 'b':
            loop_tail = loop_state[1]
            loop_line = loop_head
            loop_line_content = linecache.getline(source_file, loop_line)
            if loop_line_content.find('while') != -1:
                    return -1
            while(1):
                loop_line += 1
                if loop_line == loop_tail:
                    break
                loop_line_content = linecache.getline(source_file, loop_line)
                if loop_line_content.find('for') != -1 and search_line_status(function_index, loop_line) == 'b':
                    return -1
                if loop_line_content.find('if') != -1:
                    return -1
                if loop_line_content.find('while') != -1 and search_line_status(function_index, loop_line) == 'b':
                    return -1
            return loop_tail
    return -1


# obtain the line status based on the line num
# input: function_index, line_num
# output: line_status
def search_line_status(function_index, line_num):
    line_numbers = all_functions[function_index][2]
    for line_num_list in line_numbers:
        current_line_num = line_num_list[0]
        if current_line_num == line_num:
            line_status = line_num_list[1]
            return line_status



# extract the loop iterator
# input: function_index, line_num_list_index
# output: iterator
def loop_iterator_and_definition(function_index, line_num_list_index, unrolling_times):
    line_num = all_functions[function_index][2][line_num_list_index][0]
    line_content = linecache.getline(source_file, line_num)
    loop_control_list = line_content[line_content.find('(')+1:line_content.find(')')].split('; ')
    iterator = loop_control_list[0].split(' = ')[0].strip()
    if line_content.find('++') != -1:
        loop_definition = line_content[:line_content.find('++') - len(iterator+'; ')] + '/' + unrolling_times + '*' + unrolling_times + line_content[line_content.find('++') - len(iterator+'; '):line_content.find('++')+1] + '=' + unrolling_times + ') {\n'
        adder = str(1)
        operator = '+'
    elif line_content.find(' += ') != -1:
        loop_definition = line_content[:line_content.find(' +=') - len(iterator+'; ')] + '/' + iterator + '/' + unrolling_times + '*' + unrolling_times + line_content[line_content.find(' +=') - len(iterator+'; '):line_content.find(' ) {')] + '*' + unrolling_times + ') {\n'
        adder = loop_control_list[2].split(' += ')[1].strip()
        operator = '+'
    elif line_content.find('--') != -1:
        loop_definition = line_content[:line_content.find('--') - len(iterator+'; ')] + '/' + unrolling_times + '*' + unrolling_times + line_content[line_content.find('--') - len(iterator+'; '):line_content.find('--')+1] + '=' + unrolling_times + ') {\n'
        adder = str(1)
        operator = '-'
    elif line_content.find(' -= ') != -1:
        loop_definition = line_content[:line_content.find(' -=') - len(iterator+'; ')] + '/' + iterator + '/' + unrolling_times + '*' + unrolling_times + line_content[line_content.find(' -=') - len(iterator+'; '):line_content.find(' ) {')] + '*' + unrolling_times + ') {\n'
        adder = loop_control_list[2].split(' -= ')[1].strip()
        operator = '-'
    return iterator,loop_definition,adder,operator


# get the index with iterator in the current line
# input: line_content
# output: index list of [iterator]
def find_element_in_line(element, line_content):
    index_list = []
    remaining_line = line_content
    while (1):
        index = remaining_line.find(element)
        if index != -1:
            previous_length = len(line_content) - len(remaining_line)
            index += previous_length
            index_list.append(index)
            remaining_line = remaining_line[index+len(element):]
        else:
            return index_list

# swei: check if the input line is a variable definition (i.e., contain data types)
def is_var_definition(line_content) :
    data_type_list = ['int', 'int*', 'char', 'char*', 'double', 'double*', 'long', 'long*', 'float', 'float*']
    flag = False
    for data_type in data_type_list:
        if line_content.find(data_type) != -1:
            flag = True
            break
    return flag

# output the number of lines for the certain world content
# input: world_function_content
# output: number of lines
def final_line_count(world_function_content):
    secure_count = 0
    original_count = 0
    for function_content_list in world_function_content:
        function_content = function_content_list[1]
        secure_count += len(function_content)
    for function in all_functions:
        function_name = function[0]
        if function_name != 'main':
            line_numbers = function[2]
            original_count += len(line_numbers)
    print(original_count, secure_count, sep=',')


# add missing smc for some loop blocks
# input: function_index, current_line_index, function_status, opposite_status
# output: True: add missing SMC; False: do NOT add missing SMC
def loop_add_missing_smc(function_index, current_line_index, function_status, opposite_status):
    current_line_list = all_functions[function_index][2][current_line_index]
    current_line_num = current_line_list[0]
    loop_statements = all_functions[function_index][4]
    current_line_status = current_line_list[1]
    if current_line_status == function_status:
        for loop_state in loop_statements:
            loop_head = loop_state[0]
            loop_tail = loop_state[1]
            # check if the line is inside of the loop
            if current_line_num > loop_head and current_line_num < loop_tail:
                next_line_list = all_functions[function_index][2][current_line_index+1]
                next_line_num = next_line_list[0]
                # check if the next line is the tail of the loop block
                if next_line_num == loop_tail:
                    next_line_status = next_line_list[1]
                    if next_line_status == 'b':
                        loop_first_line_list = all_functions[function_index][2][current_line_index+1-(loop_tail - loop_head)+1]
                        loop_first_line_status = loop_first_line_list[1]
                        if loop_first_line_status == opposite_status:
                            return True
    return False


# append the content for stack functions based on shared data
# output: stack_functions
# def append_stack_functions():
#     global all_secure_shared_data
#     stack_functions.append('void pull(int *sharedData){\n')
#     stack_functions.append("}\n\n")
#     return stack_functions

# Testing Needed!!! Haven't support array in the shared data yet!!!
def sharedDataArray_statement(funtion_status, function_name):
    global all_secure_shared_data
    global all_normal_shared_data
    if funtion_status == 's':
        all_shared_data = all_secure_shared_data
    elif funtion_status == 'n':
        all_shared_data = all_normal_shared_data
    for shared_data_list in all_shared_data:
        current_function_name = shared_data_list[0]
        if current_function_name == function_name:
            shared_name = shared_data_list[2][0]
            shared_type = shared_data_list[1][0]
            return ('void *' + current_function_name +'_sharedData[] = ' + shared_name + ';\n'), ('char *' + function_name +'_sharedType[] = ' + shared_type + ';\n')


# add smc for TZm and TZb
def TZmb_add_smc():
    global all_functions
    global subfunction_in_secureMain
    secure_function_names = []
    for function in all_functions:
        function_name = function[0]
        function_status = function[1]
        if not function_name == 'main':
            if function_status == 's':
                secure_function_names.append(function_name)
    function_index = 0
    for function in all_functions:
        function_name = function[0]
        function_status = function[1]
        if not function_name == 'main':
            if function_status == 'n':
                function_line_numbers = function[2]
                sub_functions = function[7]
                for sub_function in sub_functions:
                    sub_function_name = sub_function[0]
                    if sub_function_name in secure_function_names:
                        sub_function_line_numbers = sub_function[1]
                        sub_function_arguments = []
                        sub_function_line_num_index = 0
                        for sub_function_line_num in sub_function_line_numbers:
                            sub_function_called_arguments = sub_function[2][sub_function_line_num_index]
                            sub_function_called_argTypes = extract_called_arguments_type(sub_function_called_arguments, function_index)
                            sub_function_arguments.append(sub_function_called_argTypes)
                            sub_function_line_num_index += 1
                        subfunction_in_secureMain.append([function_index, sub_function_line_numbers, sub_function[2], sub_function_arguments])
        function_index += 1


def extract_called_arguments_type(sub_function_called_arguments, function_index):
    called_argTypes = []
    line_numbers = all_functions[function_index][2]
    for called_argument in sub_function_called_arguments:
        line_num_list_index = 0
        find_flag = False
        for line_num_list in line_numbers:
            line_num = line_num_list[0]
            line_content = linecache.getline(source_file, line_num)
            if line_content.find(called_argument) != -1:
                line_content_list = line_content.strip().split(' ')
                line_content_element_index = 0
                for line_content_element in line_content_list:
                    if line_content_element.find(called_argument) != -1:
                        if line_content_element.find('[') != -1:
                            called_argTypes.append('*' + line_content_list[line_content_element_index - 1])
                        else:
                            called_argTypes.append(line_content_list[line_content_element_index - 1])
                        find_flag = True
                        break
                    line_content_element_index += 1
            if find_flag:
                break
                # if line_num_list_index == 0: # function call statement
                # else: # variable definition
            line_num_list_index += 1
    return called_argTypes


# generate normal_main.c
def generate_normal_world():
    f = open("%s/normal_main.c" % sys.argv[1],'w')
    # write the normal world includes
    for line in normal_includes:
        f.write(line)

    # write the normal world defines
    for line in normal_defines:
        f.write(line)

    # globals and stack_pointer
    f.write(stack_pointer)

    # write the constants of shared data array
    # global all_normal_shared_data
    # for shared_data_list in all_normal_shared_data:
    #     function_name = shared_data_list[0]
    #     shared_type = shared_data_list[1][0]
    #     shared_name = shared_data_list[2][0]
    #     f.write('const void* ' + function_name +'_sharedData[] = ' + shared_name + ';\n')
    #     f.write('const char* ' + function_name +'_sharedType[] = ' + shared_type + ';\n')

    # append stack_functions
    #stack_functions = append_stack_functions()

    # stack functions
    for line in stack_functions_push_statements:
        f.write(line)

    # write the normal function defines
    for line in normal_functions_content:
        if line[0] != 'main':
            for line_content in line[1][0][0]:
                if line_content == '{':
                    f.write(';')
                    break
                else:
                    f.write(line_content[0])
            f.write("\n")

    # writing normal functions
    index = 0
    for line in normal_functions_content:
        if line[0] != 'main':
            for line_content in line[1]:
                f.write(line_content[0])
            f.write("\n")
        else:
            normal_main_index = index
        index += 1

    # normal_world default functions
    for line in normal_default_functions:
        f.write(line)

    # main function
    for line in normal_main:
        f.write(line)
    # index = 0
    # for line_content in normal_functions_content[normal_main_index][1]:
    #     if line_content[0].find('TNT') == -1 and line_content[0].find('//') == -1 and index != 0:
    #         f.write(line_content[0])
    #     index += 1


    # closing the main function
    f.write(close)


# generate s_boot.c
def generate_secure_world():
    f = open("%s/s_boot.c" % sys.argv[1],'w')

    # write the secure world includes
    for line in secure_includes:
        f.write(line)

    # secure extern
    f.write(secure_extern)

    # write the constants of shared data array
    # global all_secure_shared_data
    # for shared_data_list in all_secure_shared_data:
    #     function_name = shared_data_list[0]
    #     shared_type = shared_data_list[1][0]
    #     shared_name = shared_data_list[2][0]
    #     f.write('const void* ' + function_name +'_sharedData[] = ' + shared_name + ';\n')
    #     f.write('const char* ' + function_name +'_sharedType[] = ' + shared_type + ';\n')

    # write the secure world defines
    # for line in secure_defines:
    #     f.write(line)

    # write the secure function defines
    for line in secure_functions_content:
        for line_content in line[1][0][0]:
            if line_content == '{':
                f.write(';')
                break
            else:
                f.write(line_content[0])
        f.write("\n")

    # globals and stack_pointer
    f.write(stack_pointer)

    # stack functions
    for line in stack_functions_pull_statements:
        f.write(line)

    # writing secure functions
    for line in secure_functions_content:
        for line_content in line[1]:
            f.write(line_content[0])
        f.write("\n")

    # normal_world default functions
    for line in secure_default_functions:
        f.write(line)

    # main function
    for line in secure_main:
        f.write(line)

    # closing the main function
    for line in secureWorldClose:
        f.write(line)

    # closing the main function
    f.write(close)


#template code
normal_includes = [
    "#include \"math.h\"\n",
    "#include \"uart.h\"\n",
    "#include \"printf.h\"\n",
    "#include <stddef.h>\n",
    "void *memcpy(void *dest, const void *src, size_t n)\n",
    "{\n",
    "\tchar *dp = dest;\n",
    "\tconst char *sp = src;\n",
    "\twhile (n--)\n",
        "\t\t*dp++ = *sp++;\n",
    "\treturn dest;\n",
    "}\n"
    ]

normal_defines = [
    "#define writel(v,a)   (*(volatile unsigned int *)(a) = (v))\n",
    "#define readl(a)	 (*(volatile unsigned int *)(a))\n\n"
    ]

# stack_pointer = "char *sp = (char *)0x00026000;\n\n"
stack_pointer = "char *sp = (char *)0x00026000;\n\n"

stack_functions = [
    'void pull(void *sharedData, char* sharedType[]){\n',
    '\tint i;\n',
    '\tfor (i = 0; i < sizeof(sharedData); i++) {\n',
    '\t\tif (sharedType[i][0] == \'i\')\n',
    '\t\t\t*((int *)(sharedData+i*(sizeof(int)))) = *((int *)(sp+i*(sizeof(int))));\n',
    '\t\tif (sharedType[i][0] == \'d\')\n',
    '\t\t\t*((double *)(sharedData+i*(sizeof(double)))) = *((double *)(sp+i*(sizeof(double))));\n',
    '\t\tif (sharedType[i][0] == \'f\')\n',
    '\t\t\t*((float *)(sharedData+i*(sizeof(float)))) = *((float *)(sp+i*(sizeof(float))));\n',
    '\t\tif (sharedType[i][0] == \'c\')\n',
    '\t\t\t*((char *)(sharedData+i*(sizeof(char)))) = *((char *)(sp+i*(sizeof(char))));\n',
    '\t}\n',
    '}\n\n',

    'void push(void* sharedData, char* sharedType[]){\n',
    '\tint i;\n',
    '\tfor (i = 0; i < sizeof(sharedData); i++) {\n',
    '\t\tif (sharedType[i][0] == \'i\')\n',
    '\t\t\t*((int *)(sp+i*(sizeof(int)))) = *((int *)(sharedData+i*(sizeof(int))));\n',
    '\t\tif (sharedType[i][0] == \'d\')\n',
    '\t\t\t*((double *)(sp+i*(sizeof(double)))) = *((double *)(sharedData+i*(sizeof(double))));\n',
    '\t\tif (sharedType[i][0] == \'f\')\n',
    '\t\t\t*((float *)(sp+i*(sizeof(float)))) = *((float *)(sharedData+i*(sizeof(float))));\n',
    '\t\tif (sharedType[i][0] == \'c\')\n',
    '\t\t\t*((char *)(sp+i*(sizeof(char)))) = *((char *)(sharedData+i*(sizeof(char))));\n',
    '\t}\n',
    '}\n\n',

    'void push_smc(void* sharedData, char* sharedType[]){\n',
    '\tpush(sharedData,sharedType);\n',
    '\tasm volatile(\"smc #0\\n\\t\");\n',
    '}\n\n',

    'void smc_pull(void* sharedData, char* sharedType[]){\n',
    '\tasm volatile(\"smc #0\\n\\t\");\n',
    '\tpull(sharedData,sharedType);\n',
    '}\n\n'
]

stack_functions_backup = [
    # Back Up
    "int pullInteger(int* data){\n",
	"\tint result = 0;\n",
	"\tchar type = (char)*sp;\n",
	"\tif (type == 'I'){\n",
		"\t\tsp++;\n",
		"\t\tunsigned char first = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char second = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char third = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fourth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tresult = fourth;\n",
		"\t\tresult = result << 8;\n",
		"\t\tresult ^= third;\n",
		"\t\tresult = result << 8;\n",
		"\t\tresult ^= second;\n",
		"\t\tresult = result << 8;\n",
		"\t\tresult ^= first;\n",
	"\t} else {\n",
		"\t\tuart_puts(\"Error retrieving integer off stack\\n\");\n",
	"\t}\n",
	"\treturn result;\n",
"}\n\n",
    "void pullDouble(double * result){\n",
	"\tlong long* ptr = (long long*)result;\n",
	"\tchar type = (char)*sp;\n",
	"\tif (type == 'D'){\n",
		"\t\tsp++;\n",
		"\t\tunsigned char first = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char second = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char third = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fourth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fifth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char sixth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char seventh = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char eigth = *sp;\n",
		"\t\tsp++;\n",
		"\t\t*ptr = eigth;\n"
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = seventh;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = sixth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = fifth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = fourth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = third;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = second;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = first;\n",
		"\t\t*ptr = *ptr << 8;\n",
	"\t} else {\n",
		"\t\tuart_puts(\"Error retrieving double off stack\\n\");\n",
	"\t}\n",
"}\n\n",

"void pushInteger(int* value){\n",
    "\tint* ptr = (int*)value;\n",
    "\t// getting first part\n",
    "\t*sp = 'I';\n",
    "\tsp++;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting second part \n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
"}\n\n",

"void pushDouble(double * value){\n",
    "\tlong long * ptr = (long long *)value;\n",
    "\t//getting first part\n",
    "\t*sp = 'D';\n",
    "\tsp++;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting second part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n"
    "\t// shifting bits \n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting second part\n",
    "\t*sp = *ptr;\n",
    "\tsp ++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
"}\n\n",

    "void pullString(char* string,int size){\n",
	"\tchar type = (char)*sp;\n",
	"\tif (type == 'S'){\n",
		"\t\tsp++;\n",
		"\t\tint i = 0;\n",
		"\t\tfor(i = 0; i < size; i++){\n",
			"\t\t\tchar letter = *sp;\n",
			"\t\t\tstring[i] = letter;\n",
			"\t\t\tsp++;\n",
		"\t\t}\n",
		"\t\tstring[i] = '\\0';\n",
	"\t} else {\n",
		"\t\tuart_puts(\"Error retrieving string from the stack\\n\");\n",
	"\t}\n",
"}\n\n",

"void pushString(char * string, int size){\n",
    "\t*sp = 'S';\n",
    "\tsp++;\n",
    "\tint i = 0;\n",
    "\tfor(i = 0; i < size; i++){\n",
    "\t\t*sp = string[i];\n",
    "\t\tsp++;\n",
    "\t}\n",
"}\n\n"

]

stack_functions_pull_statements = [
"void pullInteger(int* result ){\n",
    "\tchar type = (char)*sp;\n",
	"\tif (type == 'I'){\n",
		"\t\tsp++;\n",
		"\t\tunsigned char first = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char second = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char third = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fourth = *sp;\n",
		"\t\tsp++;\n",
		"\t\t*result = fourth;\n",
		"\t\t*result = *result << 8;\n",
		"\t\t*result ^= third;\n",
		"\t\t*result = *result << 8;\n",
		"\t\t*result ^= second;\n",
		"\t\t*result = *result << 8;\n",
		"\t\t*result ^= first;\n",
	"\t} else {\n",
		"\t\tuart_puts(\"Error retrieving integer off stack\\n\");\n",
    "\t}\n",
"}\n\n",


"void pullDouble(double* result){\n",
	"\tlong long* ptr = (long long*)result;\n",
	"\tchar type = (char)*sp;\n",
	"\tif (type == 'D'){\n",
		"\t\tsp++;\n",
		"\t\tunsigned char first = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char second = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char third = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fourth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fifth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char sixth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char seventh = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char eighth = *sp;\n",
		"\t\tsp++;\n",
		"\t\t*ptr = eighth;\n"
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = seventh;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = sixth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = fifth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = fourth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = third;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = second;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = first;\n",
		"\t\t*ptr = *ptr << 8;\n",
	"\t} else {\n",
		"\t\tuart_puts(\"Error retrieving double off stack\\n\");\n",
	"\t}\n",
"}\n\n",

"void pull(void* sharedData[], char* sharedType[], int array_size){\n",
    "\tint i;\n",
    "\tfor (i = 0; i < array_size; i++) {\n",
        "\t\tif (sharedType[i][0] == \'i\')\n",
            "\t\t\tpullInteger(sharedData[i]);\n",
        "\t\telse if (sharedType[i][0] == \'d\')\n",
            "\t\t\tpullDouble(sharedData[i]);\n",
    "\t}\n",
"}\n\n",

"void smc_pull(void* sharedData[], char* sharedType[], int array_size){\n",
    "\tasm volatile(\"smc #0\\n\\t\");\n",
    "\tpull(sharedData,sharedType,array_size);\n",
    "}\n\n"
]

stack_functions_push_statements = [
"void pushInteger(int* value){\n",
    "\tint* ptr = (int*)value;\n",
    "\t// getting first part\n",
    "\t*sp = 'I';\n",
    "\tsp++;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting second part \n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
"}\n\n",

"void pushDouble(double * value){\n",
    "\tlong long * ptr = (long long *)value;\n",
    "\t//getting first part\n",
    "\t*sp = 'D';\n",
    "\tsp++;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting second part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n"
    "\t// shifting bits \n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting second part\n",
    "\t*sp = *ptr;\n",
    "\tsp ++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
"}\n\n",

"void push(void* sharedData[], char* sharedType[], int array_size){\n",
    "\tint i;\n",
    "\tfor (i = 0; i < array_size; i++) {\n",
        "\t\tif (sharedType[i][0] == \'i\')\n",
            "\t\t\tpushInteger(sharedData[i]);\n",
        "\t\telse if (sharedType[i][0] == \'d\')\n",
            "\t\t\tpushDouble(sharedData[i]);\n",
    "\t}\n",
"}\n\n",

"void push_smc(void* sharedData[], char* sharedType[], int array_size){\n",
    "\tpush(sharedData,sharedType,array_size);\n",
    "\tasm volatile(\"smc #0\\n\\t\");\n",
    "}\n\n"
]

stack_functions_multi_statements = [
'void pull(void* sharedData, char* sharedType[]){\n',
    '\tint i;\n',
    '\tfor (i = 0; i < sizeof(sharedData); i++) {\n',
        '\t\tif (sharedType[i][0] == \'i\')\n',
            '\t\t\tpullInteger(&sharedData[i]);\n',
        '\t\telse if (sharedType[i][0] == \'d\')\n',
            '\t\t\tpullDouble(&sharedData[i]);\n',
    '\t}\n',
'}\n\n',

'void push(void* sharedData[], char* sharedType[]){\n',
    '\tint i;\n',
    '\tfor (i = 0; i < sizeof(sharedData); i++) {\n',
        '\t\tif (sharedType[i][0] == \'i\')\n',
            '\t\t\tpushInteger(&sharedData[i]);\n',
        '\t\telse if (sharedType[i][0] == \'d\')\n',
            '\t\t\tpushDouble(&sharedData[i]);\n',
    '\t}\n',
'}\n\n'

"void pullInteger(void* result){\n",
	"\tlong long* ptr = (long long*)result;\n",
	"\tchar type = (char)*sp;\n",
	"\tif (type == 'I'){\n",
		"\t\tsp++;\n",
		"\t\tunsigned char first = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char second = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char third = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fourth = *sp;\n",
		"\t\tsp++;\n",
		"\t\t*ptr = fourth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = third;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = second;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = first;\n",
		"\t\t*ptr = *ptr << 8;\n",
	"\t} else {\n",
		"\t\tuart_puts(\"Error retrieving double off stack\\n\");\n",
	"\t}\n",
"}\n\n",

"void pullDouble(void* result){\n",
	"\tlong long* ptr = (long long*)result;\n",
	"\tchar type = (char)*sp;\n",
	"\tif (type == 'D'){\n",
		"\t\tsp++;\n",
		"\t\tunsigned char first = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char second = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char third = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fourth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char fifth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char sixth = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char seventh = *sp;\n",
		"\t\tsp++;\n",
		"\t\tunsigned char eigth = *sp;\n",
		"\t\tsp++;\n",
		"\t\t*ptr = eigth;\n"
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = seventh;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = sixth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = fifth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = fourth;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = third;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = second;\n",
		"\t\t*ptr = *ptr << 8;\n",
		"\t\t*ptr = first;\n",
		"\t\t*ptr = *ptr << 8;\n",
	"\t} else {\n",
		"\t\tuart_puts(\"Error retrieving double off stack\\n\");\n",
	"\t}\n",
"}\n\n",

"void pushInteger(void* value){\n",
    "\tint* ptr = (int*)value;\n",
    "\t// getting first part\n",
    "\t*sp = 'I';\n",
    "\tsp++;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting second part \n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
"}\n\n",

"void pushDouble(void* value){\n",
    "\tlong long * ptr = (long long *)value;\n",
    "\t//getting first part\n",
    "\t*sp = 'D';\n",
    "\tsp++;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting second part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n"
    "\t// shifting bits \n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t// getting second part\n",
    "\t*sp = *ptr;\n",
    "\tsp ++;\n",
    "\t// shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting third part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
    "\t//shifting bits\n",
    "\t(*ptr) = (*ptr) >> 8;\n",
    "\t//getting fourth part\n",
    "\t*sp = *ptr;\n",
    "\tsp++;\n",
"}\n\n"
]

normal_default_functions = [
                                #"void uart_putc(char c)\n",
                                #"{\n",
                                #"\twhile ((readl(0xe000102c) & 0x10) != 0) {}\n",
                                #"\tif (c == '\\n') {\n",
                                #"\t\twritel('\\r',0xe0001030);\n",
                                #"\t\twhile ((readl(0xe000102c) & 0x10) != 0) {}\n",
                                #"\t}\n",
                                #"\twritel(c, 0xe0001030);\n",
                                #"}\n\n",
                                #"void uart_puts(const char *s)\n",
                                #"{\n"
                                #"\twhile (*s) {\n",
                                #"\t\tuart_putc(*s++);\n",
                                #"\t}\n",
                                #"}\n",
                                #"void uart_init(void)\n",
                                #"{\n\n",
	                            #"\twritel(0x10 | 0x4 | 0x2 | 0x1, 0xe0001000 + 0x0);\n",
	                            #"\twritel(0x20, 0xe0001000 + 0x4);\n",
	                            #"\twritel(0x56, 0xe0001000 + 0x18);	//config baud\n"
	                            #"\twritel(0x4, 0xe0001000 + 0x34);\n",
                                #"}\n\n",
                                "void normal_main(void)\n",
                                "{\n",
                                # "\tvoid* sp = (void*)0x00025000;\n",
    	                        "\tuart_init();\n"
                                "\n",
                               ]
close = "}\n"

secure_includes = [
    "#include \"math.h\"\n",
    "#include \"uart.h\"\n",
    "#include \"printf.h\"\n",
    "#include \"timer.h\"\n",
    "#include \"common.h\"\n\n",
    "#include <stddef.h>\n",
    "void *memcpy(void *dest, const void *src, size_t n)\n",
    "{\n",
    "\tchar *dp = dest;\n",
    "\tconst char *sp = src;\n",
    "\twhile (n--)\n",
        "\t\t*dp++ = *sp++;\n",
    "\treturn dest;\n",
    "}\n"
]

# secure_defines = ["#define writel(v,a)   (*(volatile unsigned int *)(a) = (v))\n",
#                                 "#define readl(a)	 (*(volatile unsigned int *)(a))\n\n",
#                                 "#define Asm __asm__ volatile\n",
#                                 "#define CP15_SET_NSACR(x)	Asm(\"mcr p15, 0, %0, c1, c1, 2\"::\"r\"(x))\n",
#                                 "#define CP15_SET_CPACR(x)	Asm(\"mcr p15, 0, %0, c1, c0, 2\"::\"r\"(x))\n",
#                                 "#define CP15_GET_SCR(x)		Asm(\"mrc p15, 0, %0, c1, c1, 0\":\"=r\"(x))\n",
#                                 "#define CP15_SET_SCR(x)		Asm(\"mcr p15, 0, %0, c1, c1, 0\"::\"r\"(x))\n\n"
#                     ]

secure_extern = "extern void monitorInit();\n\n"


secure_default_functions = [
                                #"void uart_putc(char c)\n",
                                #"{\n",
                                #"\twhile ((readl(0xe000102c) & 0x10) != 0) {}\n",
                                #"\tif (c == '\\n') {\n",
                                #"\t\twritel('\\r', 0xe0001030);\n",
                                #"\t\twhile ((readl(0xe000102c) & 0x10) != 0) {}\n",
                                #"\t}\n",
                                #"\twritel(c, 0xe0001030);\n",
                                #"}\n\n",
                                #"void uart_puts(const char * s)\n",
                                #"{\n",
                                #"\twhile (*s) {\n",
                                #"\t\tuart_putc( * s++);\n",
                                #"\t}\n",
                                #"}\n\n",
                                #"void uart_init(void)\n",
                                #"{\n",
                                #"\twritel(0x10 | 0x4 | 0x2 | 0x1, 0xe0001000 + 0x0);",
                                #"\twritel(0x20, 0xe0001000 + 0x4);\n",
                                #"\twritel(0x56, 0xe0001000 + 0x18); // config baud\n",
                                #"\twritel(0x4, 0xe0001000 + 0x34);\n",
                                #"}\n\n",
                                "int secure_main(void)\n",
                                "{\n",
                                "uart_init();\n",
	                            "timer_init();\n",
	                            "// set for non-secure can access some coprocessor reg\n",
	                            "CP15_SET_NSACR(0x00073fff);\n",
	                            "CP15_SET_CPACR(0x0fffffff);\n",
                            	"// set for SCR\n",
                            	"CP15_SET_SCR(0b110000);\n",
                            	"writel(0xdf0d, 0xf8000008);	//unlock\n",
                                "//	writel(0x0, 0xe0200018);	//config uart to secure\n",
	                            "writel(0xffff, 0xf8000404);	//config ocmram2 to non-secure\n",
                                "//	writel(0x0, 	   0xf8000400); //config ocmram1 to secure\n",
                                "//	writel(0x767b,	0xf8000910);	//lock\n",
                            	"asm volatile (\"isb\");\n",
                            	"asm volatile (\"dsb\");\n",
                            	"// Install monitor\n",
                                "//  char* dest = (char*)0x20100;\n",
                                "//	char* src  = (char*)0x1000;\n",
                                "// 	for(i=0; i<500; i++)\n",
                                "//	 	*dest++ = *src++;\n",
                            	"writel((0x1 << 7), 0xe0200018);	//config uart to secure\n",
                            	"monitorInit();\n",
                                # "\tuart_init();\n",
                                # "\t// set for non - secure can access some coprocessor reg\n",
                                # "\tCP15_SET_NSACR(0x00073fff);\n",
                                # "\tCP15_SET_CPACR(0x0fffffff);\n",
                                # "\t// set for SCR\n",
                                # "\tCP15_SET_SCR(0b110000);\n",
                                # "\twritel(0xdf0d, 0xf8000008); // unlock\n",
                                # "\t// writel(0x0, 0xe0200018); // config uart to secure\n",
                                # "\twritel(0xffff, 0xf8000404); // config ocmram2 to non - secure\n",
                                # "\t// writel(0x0, 0xf8000400); // config ocmram1 to secure\n",
                                # "\t// writel(0x767b, 0xf8000910); // lock\n",
                                # "\tasm volatile(\"isb\");\n",
                                # "\tasm volatile(\"dsb\");\n",
                                # "\twritel((0x1 << 7), 0xe0200018); // config uart to secure\n",
                                # "\tmonitorInit();\n",
                                "# if 1\n",
                                "\twhile (1) {\n",
                                # "\t\tvoid * sp = (void *)0x00025000;\n",
                                "\n"
                                ]

secureWorldClose = [
                                "\n",
                                "\t\t//Switch from SW to NW\n",
                                "\t\tasm volatile(\"smc #0\\n\\t\");",
                                "\n",
                                "\t}\n",
                                "#endif\n",
	                            "\treturn 0;\n"
                                #"}\n"
                    ]

smc = "asm volatile (\"smc #0\\n\\t\");\n"


