from TZm import *


# load the line numbers for secure and normal functions
# input: all_functions -> [[function_name, function_status, [[line_num, line_status], ...],
# [[if_head, if_tail, else_head, else_tail], ...], [[loop_head, loop_tail], ...],
# [[[original_arg_type, original_arg_name], ...]], [[original_var_type, original_var_name], ...]], ...]
# output: update line status in all functions
def TZb_load_functions_line_nums():
    for function in all_functions:
        function_name = function[0]
        if function_name != 'main':
            function_status = function[1]
            line_numbers = function[2]
            secure_line_nums = extract_line_nums(function_name)
            for line_num_list in line_numbers:
                line_num = line_num_list[0]
                # swei
                if line_num in secure_line_nums or is_var_definition(linecache.getline(source_file, line_num)):
                    #linecache.getline(source_file, line_num).find('int') != -1 or linecache.getline(source_file, line_num).find('int*') != -1 or \
                    #linecache.getline(source_file, line_num).find('double') != -1 or linecache.getline(source_file, line_num).find('double*') != -1 or \
                    #linecache.getline(source_file, line_num).find('char') != -1 or linecache.getline(source_file, line_num).find('char*') != -1 or \
                    #linecache.getline(source_file, line_num).find('long') != -1 or linecache.getline(source_file, line_num).find('long*') != -1 or \
                    #linecache.getline(source_file, line_num).find('float') != -1 or linecache.getline(source_file, line_num).find('float*') != -1:
                        line_num_list[1] = function_status
                else:
                    line_num_list[1] = 'x'
    # add missing bracketsR
    add_missing_brackets()
    remove_empty_bracket_blocks()
    # print('TZb: ', all_functions)


# add missing brackets
# input: all_functions -> [[function_name, function_status, [[line_num, line_status], ...],
# [[if_head, if_tail, else_head, else_tail], ...], [[loop_head, loop_tail], ...],
# [[[original_arg_type, original_arg_name], ...]], [[original_var_type, original_var_name], ...]], ...]
# output: update line status in all functions
def add_missing_brackets():
    for function in all_functions:
        function_name = function[0]
        if function_name != 'main':
            function_status = function[1]
            line_numbers = function[2]
            conditional_statements = function[3]
            loop_statements = function[4]
            for line_num_list in line_numbers:
                # add if-else missing bracket
                for if_else_line_nums in conditional_statements:
                    if line_num_list[0] in if_else_line_nums and line_num_list[1] == 'x':
                        line_num_list[1] = function_status
                # add loop missing bracket
                for for_line_nums in loop_statements:
                    if line_num_list[0] in for_line_nums and line_num_list[1] == 'x':
                        line_num_list[1] = function_status


# remove the empty bracket blocks
# input: all_functions
# output: updated line status by removing empty bracket blocks
def remove_empty_bracket_blocks():
    for function in all_functions:
        function_name = function[0]
        if function_name != 'main':
            line_numbers = function[2]
            conditional_statements = function[3]
            loop_statements = function[4]
            while(1):
                status_update_flag = False
                for conditional_state in conditional_statements:
                    if len(conditional_state) == 4:
                        if_head = conditional_state[0]
                        if_tail = conditional_state[1]
                        else_head = conditional_state[2]
                        else_tail = conditional_state[3]
                        if remove_empty_conditional_block(line_numbers, if_head, if_tail, else_head, else_tail) and line_numbers[if_head - line_numbers[0][0]][1] != 'x':
                            line_numbers[if_head - line_numbers[0][0]][1] = 'x'
                            line_numbers[if_tail - line_numbers[0][0]][1] = 'x'
                            line_numbers[else_head - line_numbers[0][0]][1] = 'x'
                            line_numbers[else_tail - line_numbers[0][0]][1] = 'x'
                            status_update_flag = True
                    elif len(conditional_state) == 2:
                        if_head = conditional_state[0]
                        if_tail = conditional_state[1]
                        if_head_index = if_head - line_numbers[0][0]
                        if_tail_index = if_tail - line_numbers[0][0]
                        if not block_is_call(if_head_index, if_tail_index, line_numbers) and line_numbers[if_head_index][1] != 'x':
                            line_numbers[if_head_index][1] = 'x'
                            line_numbers[if_tail_index][1] = 'x'
                            status_update_flag = True
                for loop_state in loop_statements:
                    loop_head = loop_state[0]
                    loop_tail = loop_state[1]
                    loop_head_index = loop_head - line_numbers[0][0]
                    loop_tail_index = loop_tail - line_numbers[0][0]
                    if not block_is_call(loop_head_index, loop_tail_index, line_numbers) and line_numbers[loop_head_index][1] != 'x':
                        line_numbers[loop_head_index][1] = 'x'
                        line_numbers[loop_tail_index][1] = 'x'
                        status_update_flag = True
                if not status_update_flag:
                    break


# remove the empty conditional block
# input: line_numbers, if_head, if_tail, else_head, else_tail
# output: True: remove; False: keep
def remove_empty_conditional_block(line_numbers, if_head, if_tail, else_head, else_tail):
    if_head_index = if_head - line_numbers[0][0]
    if_tail_index = if_tail - line_numbers[0][0]
    else_head_index = else_head - line_numbers[0][0]
    else_tail_index = else_tail - line_numbers[0][0]

    if_flag = block_is_call(if_head_index, if_tail_index, line_numbers)
    else_flag = block_is_call(else_head_index, else_tail_index, line_numbers)

    if not if_flag or not else_flag:
        return True
    else:
        return False


# check if the block is called or not
# input: block head index, block tail index, line_numbers
# output: True: block is called; False: block is not called
def block_is_call(head_index, tail_index, line_numbers):
    flag = False
    for state in line_numbers[head_index+1:tail_index]:
        if state[1] != 'x':
            flag = True
            break
    return flag


# extract line numbers in the secure function
# input: function_name and taintAnalysis_content
# output: line_numbers
def extract_line_nums(function_name):
    line_numbers = []
    for line in taintAnalysis_content:
        split_pipe = line.split("|")
        if len(split_pipe) >= 4:
            function = split_pipe[0].split(" ")[1]
            if function == function_name:
                # extract line number of the function in the source code
                line_num = int(split_pipe[0][split_pipe[0].find("(")+1:split_pipe[0].find(")")].split(":")[1])
                if line_num not in line_numbers:
                    line_numbers.append(line_num)
    line_numbers.sort()
    return line_numbers


# trim unused parameters and variables
# input: all_functions
# output:
def trim_unused_parameters_variables():
    function_index = 0
    for function in all_functions:
        # append empty list for appending arguments and variables for secure and normal apps
        function[5].append([])
        function[6].append([])
        function_status = function[1]
        if function_status == 's':
            update_secure_normal_arg_var(function_index, function_status, 's')
        elif function_status == 'b':
            function[5].append([])
            function[5].append([])
            function[6].append([])
            function[6].append([])
            function[6].append([])
            update_secure_normal_arg_var(function_index, function_status, 's')
            update_secure_normal_arg_var(function_index, function_status, 'n')
            update_shared_arg_var(function_index, 'arg')
            update_shared_arg_var(function_index, 'var')
        function_index += 1


# check if the variable or argument is tainted or not:
def if_var_arg_is_taint(taint_arg_var_list,arg_var):
    arg_var_name = arg_var[1]
    for arg_var_list in taint_arg_var_list:
        taint_arg_var_name = arg_var_list[1]
        if arg_var_name == taint_arg_var_name:
            return False
        elif arg_var_name.find('[') != -1:
            if taint_arg_var_name.find(arg_var_name[:arg_var_name.find('[')]) != -1:
                return False
        elif arg_var_name.find('*') != -1:
            if taint_arg_var_name.find(arg_var_name[arg_var_name.find('*')+1:]) != -1:
                return False
    return True


# obtain shared arguments and variables
# input: function_index in all_functions
# output: update shared_arg and shared_var
def update_shared_arg_var(function_index, list_type):
    if list_type == 'arg':
        list_index = 5
    elif list_type == 'var':
        list_index = 6
    taint_arg_var_list = all_functions[function_index][list_index][1]
    secure_arg_var_list = all_functions[function_index][list_index][2]
    normal_arg_var_list = all_functions[function_index][list_index][3]
    # append empty list into shared_arg or shared_var
    all_functions[function_index][list_index].append([])
    for secure_arg_var in secure_arg_var_list:
        if secure_arg_var in normal_arg_var_list and if_var_arg_is_taint(taint_arg_var_list,secure_arg_var):
            all_functions[function_index][list_index][4].append(secure_arg_var)
        else:
            secure_arg_var_name = secure_arg_var[1]
            if secure_arg_var_name.find('*') != -1:
                for normal_arg_var in normal_arg_var_list:
                    normal_arg_var_name = normal_arg_var[1]
                    if normal_arg_var_name.find(secure_arg_var_name[1:]) != -1:
                        all_functions[function_index][list_index][4].append(secure_arg_var)
            elif secure_arg_var_name.find('[') != -1:
                for normal_arg_var in normal_arg_var_list:
                    normal_arg_var_name = normal_arg_var[1]
                    if normal_arg_var_name.find(secure_arg_var_name[:secure_arg_var_name.find('[')]) != -1:
                        all_functions[function_index][list_index][4].append(secure_arg_var)
    remove_iterator_in_shared_list(function_index, list_index)


# remove iterators in the shared_arg or shared_var
# input: function_index in all_functions
# output: update shared_arg and shared_var
def remove_iterator_in_shared_list(function_index, list_index):
    if len(all_functions[function_index][list_index]) >= 5:
        shared_list = all_functions[function_index][list_index][4]
    if len(all_functions[function_index][6]) >= 6:
        iterator_list = all_functions[function_index][6][5]
    else:
        return
    shared_index = 0
    if shared_list:
        while(1):
            shared_data = shared_list[shared_index]
            shared_name = shared_data[1]
            if shared_name in iterator_list:
                del shared_list[shared_index]
            else:
                shared_index += 1
            if shared_index == len(shared_list):
                break


# check line content for used arguments and variables in secure and normal apps
# input: function_index in all_functions
# output: update secure_arg, secure_var, normal_arg, and normal_var in all_functions
def update_secure_normal_arg_var(function_index, function_status, function_type):
    line_numbers = all_functions[function_index][2]
    for line_num_list in line_numbers:
        line_num = line_num_list[0]
        line_status = line_num_list[1]
        if line_status == function_type or line_status == 'b':
            line_content = linecache.getline(source_file, line_num)
            line_content_list = line_content.strip().split(' ')
            # first, skip the function definition and the variable definition, and then, check the line content for arguments and variables
            # swei
            if is_var_definition(line_content) == False:
            #if 'int' not in line_content_list and 'int*' not in line_content_list and \
             #               'double' not in line_content_list and 'double*' not in line_content_list and \
             #               'char' not in line_content_list and 'char*' not in line_content_list and \
             #               'long' not in line_content_list and 'long*' not in line_content_list and \
             #               'float' not in line_content_list and 'float*' not in line_content_list:
                append_arg_var(function_index, function_status, line_content, function_type)


# append used arguments and variables for secure and normal apps
# input: function_index, line_content_list, function_type in all_functions
# output: update secure_arg, secure_var, normal_arg, and normal_var in the certain function
def append_arg_var(function_index, function_status, line_content, function_type):
    line_content_list = line_content.strip().split(' ')
    if sys.argv[3] == '1':
        if function_type == 's':
            arg_var_list_index = 2
        elif function_type == 'n':
            arg_var_list_index = 3
    else:
        arg_var_list_index = 1
    for line_content_element in line_content_list:
        line_content_element = line_content_element.split(';')[0]
        if line_content_element.find('[') == -1:
            append_to_list(function_index, arg_var_list_index, line_content_element)
        else:
            line_content_element_1 = line_content_element.split('[')[0]
            line_content_element_2 = line_content_element.split('[')[1].split(']')[0]
            if line_content_element_2.isdigit():
                if line_content_element_1.find('(') == -1:
                    append_to_list(function_index, arg_var_list_index, line_content_element)
            else:
                if line_content_element_2:
                # append_to_list(function_index, arg_var_list_index, line_content_element_1)
                    append_to_list(function_index, arg_var_list_index, line_content_element_2)
                    append_to_list(function_index, arg_var_list_index, line_content_element)
                else:
                    append_to_list(function_index, arg_var_list_index, line_content_element_1)
    if function_status == 'b' and function_type == 's':
        if line_content.find('for') != -1:
            extract_iterator(function_index, line_content)


# append to list for variables and arguments
# input: function_index, arg_var_list_index, line_content_element
# output: appending
def append_to_list(function_index, arg_var_list_index, line_content_element):
    if not line_content_element.isdigit():
        original_arguments_index = arg_var_in_arguments_variables(function_index, 'arg', line_content_element)
        if original_arguments_index != -1:
            if all_functions[function_index][5][0][original_arguments_index] not in all_functions[function_index][5][arg_var_list_index]:
                if line_content_element.isalpha() or line_content_element.find('_') != -1 or \
                                line_content_element.find('[') != -1 or \
                        (line_content_element.find('*') != -1 and line_content_element != '*'):

                    all_functions[function_index][5][arg_var_list_index].append([all_functions[function_index][5][0][original_arguments_index][0],line_content_element])
        else:
            original_variables_index = arg_var_in_arguments_variables(function_index, 'var', line_content_element)
            if original_variables_index != -1:
                if all_functions[function_index][6][0][original_variables_index] not in all_functions[function_index][6][arg_var_list_index]:
                    # if line_content_element.find('+') == -1 or line_content_element.find('-') == -1 or line_content_element.find('=') == -1 or line_content_element.find('_') != -1 or \
                    #                 line_content_element.find('[') != -1 or \
                    #     (line_content_element.find('*') != -1 and line_content_element != '*'):
                    if line_content_element.find('(') == -1 and line_content_element.find(')') == -1 \
                            and line_content_element.find('+') == -1 and line_content_element.find('-') == -1 \
                            and line_content_element.find('=') == -1 and line_content_element != '*':
                        if line_content_element != ']':
                            if [all_functions[function_index][6][0][original_variables_index][0],line_content_element] not in all_functions[function_index][6][arg_var_list_index]:
                                all_functions[function_index][6][arg_var_list_index].append([all_functions[function_index][6][0][original_variables_index][0],line_content_element])
    # print(all_functions[function_index][6][arg_var_list_index])


# extract iterator in current line
# input: function_index, line_content_list
# output: append iterators in the iterator
def extract_iterator(function_index, line_content):
    loop_first_state = line_content[line_content.find('(')+1:line_content.find(';')].strip()
    iterator = loop_first_state.split(' = ')[0]
    if iterator not in all_functions[function_index][6][5]:
        all_functions[function_index][6][5].append(iterator)


# check if the variable is in arguments list or not
# input: variable
# output: index in argument or variable list
def arg_var_in_arguments_variables(function_index, list_type, argument_variable):
    if list_type == 'arg':
        list_index = 5
    elif list_type == 'var':
        list_index = 6
    original_arg_var_index = 0
    for original_arg_var in all_functions[function_index][list_index][0]:
        original_arg_var_name = original_arg_var[1]
        if argument_variable.find('[') == -1:
            if arg_var_find(original_arg_var_name, argument_variable):
                return original_arg_var_index
        else:
            argument_variable_1 = argument_variable.split('[')[0]
            argument_variable_2 = argument_variable.split('[')[1].split(']')[0]
            if arg_var_find(original_arg_var_name, argument_variable_1):
                return original_arg_var_index
            elif (not argument_variable_2.isdigit()) and arg_var_find(original_arg_var_name, argument_variable_2):
                return original_arg_var_index
        original_arg_var_index += 1
    return -1


# check if the two variables are the same
# input: original_name, target_name
# output: True: find; False: not find
def arg_var_find(original_name, target_name):
    if not original_name or not target_name:
        return False
    if original_name.find(target_name) != -1 or target_name.find(original_name) != -1 or \
            original_name.find(target_name.split('[')[0]) != -1 or target_name.find(original_name.split('[')[0]) != -1:
        return True
    else:
        if original_name.find('*') != -1:
            if target_name.find(original_name.split('*')[1]) != -1:
                return True
        if target_name.find('*') != -1:
            if original_name.find(target_name.split('*')[1]) != -1:
                return True
    return False