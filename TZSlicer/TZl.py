from TZb import *


# load the line numbers for secure and normal functions
# input: all_functions
# output: update line status in all functions
def TZl_load_functions_line_nums():
    function_index = 0
    for function in all_functions:
        function_status = function[1]
        both_flag = False
        if function_status == 's':
            # append empty list for potential taint_arg into the arguments and variables in all_functions
            function[5].append([])
            function[6].append([])
            function_name = function[0]
            # extract tainted line numbers
            secure_line_nums = extract_taint_line_nums(function_name, function_index)
            line_numbers = function[2]
            for line_num_list in line_numbers:
                line_num = line_num_list[0]
                if line_num_list[1] != 'x':
                    if (line_num not in secure_line_nums and \
                        # swei
                        is_var_definition(linecache.getline(source_file, line_num)) == False and \
                            #linecache.getline(source_file, line_num).find('int') == -1 and linecache.getline(source_file, line_num).find('int*') == -1 and \
                             #       linecache.getline(source_file, line_num).find('double') == -1 and linecache.getline(source_file, line_num).find('double*') == -1 and \
                             #       linecache.getline(source_file, line_num).find('char') == -1 and linecache.getline(source_file, line_num).find('char*') == -1 and \
                             #       linecache.getline(source_file, line_num).find('long') == -1 and linecache.getline(source_file, line_num).find('long*') == -1 and \
                             #       linecache.getline(source_file, line_num).find('float') == -1 and linecache.getline(source_file, line_num).find('float*') == -1 and \
                        line_num_list != line_numbers[-1]):
                        line_num_list[1] = 'n'
                        both_flag = True
                    else:
                        line_num_list[1] = 's'
                    if (linecache.getline(source_file, line_num).find('if') != -1 or linecache.getline(source_file, line_num).find('else') != -1 or
                                linecache.getline(source_file, line_num).find('}') != -1 or
                                linecache.getline(source_file, line_num).find('for') != -1 or linecache.getline(source_file, line_num).find('while') != -1 or
                                # swei
                                is_var_definition(linecache.getline(source_file, line_num))
                                # linecache.getline(source_file, line_num).find('int') != -1 or linecache.getline(source_file, line_num).find('int*') != -1 or \
                                #linecache.getline(source_file, line_num).find('double') != -1 or linecache.getline(source_file, line_num).find('double*') != -1 or \
                                #linecache.getline(source_file, line_num).find('char') != -1 or linecache.getline(source_file, line_num).find('char*') != -1) or \
                                #linecache.getline(source_file, line_num).find('long') != -1 or linecache.getline(source_file, line_num).find('long*') != -1 or \
                                #linecache.getline(source_file, line_num).find('float') != -1 or linecache.getline(source_file, line_num).find('float*') != -1)
                        and line_num_list[1] != 'x'):
                            line_num_list[1] = 'b'
            if both_flag:
                # change the function status
                function[1] = 'b'
                # change the line status for the function head and tail
                line_numbers[0][1] = 'b'
                line_numbers[-1][1] = 'b'
            # remove empty conditional and loop blocks
            while(1):
                status_update_flag = False
                for conditional_state in function[3]:
                    if len(conditional_state) == 2:
                        status_head = function[2][conditional_state[0] - function[2][0][0]][1]
                        status_content = function[2][conditional_state[0] + 1 - function[2][0][0]][1]
                        if remove_empty_block(function_index, conditional_state) and status_head != status_content:
                            status_update_flag = True
                    elif len(conditional_state) == 4:
                        # status_if_head = function[2][conditional_state[0] - function[2][0][0]][1]
                        # status_if_content = function[2][conditional_state[0] + 1 - function[2][0][0]][1]
                        status_else_head = function[2][conditional_state[2] - function[2][0][0]][1]
                        status_else_content = function[2][conditional_state[2] + 1 - function[2][0][0]][1]
                        if_head_index = conditional_state[:2][0] - all_functions[function_index][2][0][0]
                        if_tail_index = conditional_state[:2][1] - all_functions[function_index][2][0][0]
                        else_head_index = conditional_state[2:][0] - all_functions[function_index][2][0][0]
                        else_tail_index = conditional_state[2:][1] - all_functions[function_index][2][0][0]
                        if block_in_same_world(function_index, if_head_index, if_tail_index) and block_in_same_world(function_index, else_head_index, else_tail_index):
                            if remove_empty_block(function_index, conditional_state[2:]) and status_else_head != status_else_content and status_else_head != 'x':
                                status_update_flag = True
                                remove_empty_block(function_index, conditional_state[:2])
                for loop_state in function[4]:
                    status_head = function[2][loop_state[0] - function[2][0][0]][1]
                    status_content = function[2][loop_state[0] + 1 - function[2][0][0]][1]
                    if remove_empty_block(function_index, loop_state) and status_head != status_content:
                        status_update_flag = True
                if not status_update_flag:
                    break
        function_index += 1
    # print('TZl: ', all_functions)


# remove empty block
# input: statement
# output: update line status in all_functions
def remove_empty_block(function_index, statement):
    head = statement[0]
    tail = statement[1]
    head_index = head - all_functions[function_index][2][0][0]
    tail_index = tail - all_functions[function_index][2][0][0]
    if block_in_same_world(function_index, head_index, tail_index):
        status = all_functions[function_index][2][head_index+1][1]
        if all_functions[function_index][2][head_index][1] != 'x':
            all_functions[function_index][2][head_index][1] = status
            all_functions[function_index][2][tail_index][1] = status
        return True
    return False


# check if the content inside the block is in the same world or not
# input: function_index, block_head, block_tail
# output: True: same world; False: different worlds
def block_in_same_world(function_index, head_index, tail_index):
    head_index += 1
    last_line_status = all_functions[function_index][2][head_index][1]
    # last_line_content = linecache.getline(source_file, all_functions[function_index][2][head_index][0])
    while(1):
        # if last_line_content.find('for') != -1 or last_line_status == 'x' or last_line_content.find('while') != -1 or last_line_content.find('if') != -1:
        if last_line_status == 'b' or last_line_status == 'x':
            head_index += 1
        else:
            last_line_status = all_functions[function_index][2][head_index][1]
            break
        if head_index == tail_index:
            return True
        last_line_status = all_functions[function_index][2][head_index][1]
        # last_line_content = linecache.getline(source_file, all_functions[function_index][2][head_index][0])
    for line_index in range(head_index+1,tail_index):
        current_line_status = all_functions[function_index][2][line_index][1]
        # current_line_content = linecache.getline(source_file, all_functions[function_index][2][line_index][0])
        # if last_line_status != current_line_status and current_line_status != 'x' and current_line_content.find('for') == -1 and current_line_content.find('while') == -1 and current_line_content.find('if') == -1:
        if last_line_status != current_line_status and current_line_status != 'b' and current_line_status != 'x' :
            return False
        # if current_line_content.find('for') == -1 and current_line_content.find('while') == -1 and current_line_content.find('if') == -1:
        if current_line_status != 'b' and current_line_status != 'x':
            last_line_status = current_line_status
    # if last_line_status == 'x':
    #     return False
    return True


# extract taint-related line numbers in the secure function
# input: function_name and function_index in all_functions
# output: line_numbers
def extract_taint_line_nums(function_name, function_index):
    line_numbers = []
    index = 0
    for line in taintAnalysis_content:
        split_pipe = line.split("|")
        if (len(split_pipe) >= 4):
            function = split_pipe[0].split(" ")[1]
            if function == function_name:
                # extract taint-related line number of the function in C source file
                line_num = int(split_pipe[0][split_pipe[0].find("(")+1:split_pipe[0].find(")")].split(":")[1])
                # if taintAnalysis_content[index+1].split("|")[0].find(" <- ") != -1: # find the taint information flow line
                # swei
                if taintAnalysis_content[index + 1].find(" <- ") != -1:  # find the taint information flow line
                    # find the tainted arguments and variables
                    for flow_line in taintAnalysis_content[index+1].split(' <- '): # traverse the parameter and variable list, and find the tainted parameter/variable
                        # find the tainted arguments
                        arguments = all_functions[function_index][5]
                        original_arg = arguments[0]
                        for arg in original_arg:
                            arg_name = arg[1]
                            if flow_line == arg_name or flow_line.find(arg_name+'[') != -1 or ('*' + flow_line.split('[')[0]) == arg_name:
                                if arg not in arguments[1]:
                                    arguments[1].append(arg)
                                    break
                        # find the tainted variables
                        variables = all_functions[function_index][6]
                        original_var = variables[0]
                        for var in original_var:
                            var_name = var[1]
                            if flow_line == var_name or flow_line.find(var_name+'[') != -1 or ('*' + flow_line.split('[')[0]) == var_name or var_name.find(flow_line.split('[')[0]) != -1:
                                if var not in variables[1]:
                                    variables[1].append(var)
                                    break
                    if line_num not in line_numbers:
                        line_numbers.append(line_num)
        index += 1

    # traverse the source code and taint the line numbers with the tainted variable assignment
    for line_num_list in all_functions[function_index][2]:
        # line_num_list = all_functions[function_index][2][line_num_index]
        line_num = line_num_list[0]
        line_content = linecache.getline(source_file, line_num)
        if line_content.find('for') != -1:
            loop_termination = line_content[line_content.find('(')+1:line_content.find(') {')].split('; ')[1]
            loop_termination_variable = extract_loop_termination_variable(loop_termination)
            if argument_variable_isTainted(function_index, loop_termination_variable):
                loop_head = line_num
                loop_tail = find_loop_range(function_index, loop_head)
                for loop_line in range(loop_head,loop_tail+1):
                    if loop_line not in line_numbers:
                        line_numbers.append(loop_line)
        else:
            if line_content.find(' = ') != -1:
                assigning_argument_variable = line_content.split(' = ')[1].split(';')[0]
                assigned_argument_variable = line_content.split(' = ')[0].strip()
                if not assigning_argument_variable.isdigit() and argument_variable_isTainted(function_index, assigning_argument_variable):
                    # if line_num not in line_numbers:
                    #     line_numbers.append(line_num)
                    original_arg_index = arg_var_in_arguments_variables(function_index, 'arg', assigned_argument_variable)
                    if original_arg_index != -1:
                        original_arg_name = all_functions[function_index][5][0][original_arg_index][1]
                        if original_arg_name.find('*') != -1 or original_arg_name.find('[') != -1:
                            if assigned_argument_variable.find('*') != -1 or assigned_argument_variable.find('[') != -1:
                                if line_num not in line_numbers:
                                    line_numbers.append(line_num)
                        else:
                            if line_num not in line_numbers:
                                line_numbers.append(line_num)
                    else:
                        original_var_index = arg_var_in_arguments_variables(function_index, 'var', assigned_argument_variable)
                        if original_var_index != -1:
                            original_var_name = all_functions[function_index][6][0][original_var_index][1]
                            if original_var_name.find('*') != -1 or original_var_name.find('[') != -1:
                                if assigned_argument_variable.find('*') != -1 or assigned_argument_variable.find('[') != -1:
                                    if line_num not in line_numbers:
                                        line_numbers.append(line_num)
                            else:
                                if line_num not in line_numbers:
                                    line_numbers.append(line_num)
                    # check if the assigned argument/variable is in the tainted list already
                    if not argument_variable_isTainted(function_index, assigned_argument_variable):
                    # add the assigned argument/variable into the tainted list (i.e, taint_arg/taint_var)
                        original_arg_index = arg_var_in_arguments_variables(function_index, 'arg', assigned_argument_variable)
                        if original_arg_index != -1:
                            # append the new added argument type and name into all_functions
                            all_functions[function_index][5][1].append(all_functions[function_index][5][0][original_arg_index])
                        else:
                            original_var_index = arg_var_in_arguments_variables(function_index, 'var', assigned_argument_variable)
                            if original_var_index != -1:
                                # append the new added variable type and name into all_functions
                                all_functions[function_index][6][1].append(all_functions[function_index][6][0][original_var_index])

    # double-check: according to the taint argument/variable list, add the line number if the assigned argument is tainted
    # this "double-check" process is to ignore the lifespan of the tainted variable
    for line_num_list in all_functions[function_index][2]:
        line_num = line_num_list[0]
        line_content = linecache.getline(source_file, line_num)
        if line_content.find(' = ') != -1:
            assigned_argument_variable = line_content.split(' = ')[0].strip()
            if argument_variable_isTainted(function_index, assigned_argument_variable):
                original_arg_index = arg_var_in_arguments_variables(function_index, 'arg', assigned_argument_variable)
                if original_arg_index != -1:
                    original_arg_name = all_functions[function_index][5][0][original_arg_index][1]
                    if original_arg_name.find('*') != -1 or original_arg_name.find('[') != -1:
                        if assigned_argument_variable.find('*') != -1 or assigned_argument_variable.find('[') != -1:
                            if line_num not in line_numbers:
                                line_numbers.append(line_num)
                    else:
                        if line_num not in line_numbers:
                            line_numbers.append(line_num)
                else:
                    original_var_index = arg_var_in_arguments_variables(function_index, 'var', assigned_argument_variable)
                    if original_var_index != -1:
                        original_var_name = all_functions[function_index][6][0][original_var_index][1]
                        if original_var_name.find('*') != -1 or original_var_name.find('[') != -1:
                            if assigned_argument_variable.find('*') != -1 or assigned_argument_variable.find('[') != -1:
                                if line_num not in line_numbers:
                                    line_numbers.append(line_num)
                        else:
                            if line_num not in line_numbers:
                                line_numbers.append(line_num)
        elif line_content.find('return ') != -1:
            returned_argument_variable = line_content.split('return ')[1].split(';')[0]
            if not returned_argument_variable.isdigit() and argument_variable_isTainted(function_index, returned_argument_variable):
                if line_num not in line_numbers:
                    line_numbers.append(line_num)
    line_numbers.sort()
    return line_numbers


# extract the termination variable in the loop statement
# input: loop_termination
# output: loop_termination_variable
def extract_loop_termination_variable(loop_termination):
    if loop_termination.find('<') != -1 and loop_termination.find('<=') == -1:
        loop_termination_variable = loop_termination.split(' < ')[1]
        return loop_termination_variable
    elif loop_termination.find('<=') != -1 and loop_termination.find('<') == -1:
        loop_termination_variable = loop_termination.split(' <= ')[1]
        return loop_termination_variable
    elif loop_termination.find('>') != -1 and loop_termination.find('>=') == -1:
        loop_termination_variable = loop_termination.split(' > ')[1]
        return loop_termination_variable
    elif loop_termination.find('>=') != -1 and loop_termination.find('>') == -1:
        loop_termination_variable = loop_termination.split(' >= ')[1]
        return loop_termination_variable


# obtain the line tail of the loop structure
# input: function_index, line_num
# output: loop_tail
def find_loop_range(function_index, loop_head):
    for loop_state in all_functions[function_index][4]:
        if loop_head in loop_state != -1:
            return loop_state[1]


# check if the termination variable for the loop statement is tainted or not
# input: function_index, variable
# output: True: tainted; False: not tainted
def argument_variable_isTainted(function_index, variable):
    # check arguments
    for taint_arg in all_functions[function_index][5][1]:
        taint_arg_name = taint_arg[1]
        if arg_var_find(taint_arg_name, variable):
            return True

    # check variables
    for taint_var in all_functions[function_index][6][1]:
        taint_var_name = taint_var[1]
        if arg_var_find(taint_var_name, variable):
            return True
    return False


# according to the subfunction call, update the parent function status
# input: slice_type
# output:
def update_function_status(slice_type):
    function_index = 0
    for function in all_functions:
        function_name = function[0]
        if function_name != 'main':
            subfunction_call = function[7]
            for subfunction_list in subfunction_call:
                subfunction_name = subfunction_list[0]
                subfunction_line_num_list = subfunction_list[1]
                subfunction_index = check_subfunction_call(subfunction_name)
                subfunction_status = all_functions[subfunction_index][1]
                function_status = function[1]
                if slice_type == 'TZm' or slice_type == 'TZb':
                    if function_status == 'n' and subfunction_status == 's':
                        function[1] = 's'
                        # update line number status
                        update_line_number_status(function_index)
                elif slice_type == 'TZl':
                    if function_status == 'n' and subfunction_status == 's':
                        function[1] = 's'
                        # update line number status
                        update_line_number_status(function_index)
                    # index = 0
                    # for subfunction_line_num in subfunction_line_num_list:
                    #     subfunction_arguments = subfunction_list[2][index]
                    #     for arg in subfunction_arguments:
                    #         # check if the arguments in subfunction call is tainted
                    #         if subfunction_status != function_status:
                    #             if function_status != 'n':
                    #                 if argument_variable_isTainted(function_index, arg):
                    #                     all_functions[subfunction_index][1] = 's'
                    #             else:
                    #                 function[1] = 's'
                    #     index += 1
        function_index += 1


# update line num status
# input: function_index, all_functions
# output: update line num status
def update_line_number_status(function_index):
    function_status = all_functions[function_index]
    line_numbers = all_functions[function_index][2]
    for line_num_list in line_numbers:
        line_num_list[1] = 's'
