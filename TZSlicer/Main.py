from TZl import *

read_taintAnalysis_log()
determine_functions()
TZm_load_functions_line_nums()
extract_if_else_statements()
extract_loop_statements()
extract_arguments_variables_for_functions()
# if (sys.argv[2] == '0' and sys.argv[3] == '0') or (sys.argv[2] == '1' and sys.argv[3] == '0'):
# TZmb_add_smc()
subfunction_call_in_secureMain()
if sys.argv[2] == '1':
    TZb_load_functions_line_nums()
if sys.argv[3] == '1':
    # add_secureMain()
    TZl_load_functions_line_nums()
# if sys.argv[2] == '0' and sys.argv[3] == '0':
#     update_function_status('TZm')
# if sys.argv[2] == '1' and sys.argv[3] == '0':
#     update_function_status('TZb')
# if sys.argv[2] == '1' and sys.argv[3] == '1':
#     update_function_status('TZl')
if sys.argv[2] == '1':
    trim_unused_parameters_variables()
parse()
generate_normal_world()
generate_secure_world()