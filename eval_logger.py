import time

class EvalLogger:
    def __init__(self, evaluation = False, program_name = '') -> None:
        self.evaluation = evaluation
        self.program_name = program_name
        self.log_file = f"{self.program_name}_output.log"
        self.init_log()
        self.start_times = {}
        self.elapsed_times = {}

    def init_log(self):
        with open(self.log_file, 'w') as log:
            print('Cleared evaluation log file')
        return
    
    def print(self):
        print(f'Evaluation: {self.evaluation}')
        print(f'Program: {self.program_name}')
        print(f'Log File: {self.log_file}')
        
    def start_timing(self, label):
        if not self.evaluation:
            return
        self.start_times[label] = time.time()
    
    def stop_timing(self, label):
        if not self.evaluation:
            return None
        if label in self.start_times:
            elapsed_time = time.time() - self.start_times[label]
            self.elapsed_times[label] = elapsed_time
            #print(f'{label} took {elapsed_time} seconds')
            return elapsed_time
        return None
    
    def write_to_log(self, total_time, log_type, extra):
        if not self.evaluation:
            return
        #log_type = 'chain', 'extraction', 'num_dll', 'dll_name',
        # 'failed_dll', 'classification', DLL_Extraction
        # extra = ['g','a','v','s','d','m','!','@']
        if (log_type == 'chain'):
            if (extra == 'g'):
                chain_type = 'HeavanGatex32(g)'
            elif (extra == 'a'):
                chain_type = 'genWinSyscallNtAllocateVirtualMemory(a)'
            elif (extra == 'v'):
                chain_type = 'genWinSyscallNtProtectVirtualMemory(v)'
            elif (extra == 's'):
                chain_type = 'genShellcodelessROP_System(s)'
            elif (extra == 'd'):
                chain_type = 'genShellcodelessROP_GetProc(d)'
            elif (extra == 'm'):
                chain_type = 'genMovDerefVP(m)'
            elif (extra == '!'):
                chain_type = 'genVirtualProtectPushad(!)'
            elif (extra == '@'):
                chain_type = 'genVirtualAllocPushad(@)'
            elif (extra == '#'):
                chain_type = 'genWinExecPushad(#)'
            elif (extra == '$'):
                chain_type = 'genDeleteFileAPushad($)'
            else:
                chain_type = 'UNKNOWN_CHAIN_TYPE'

            try:
                with open(self.log_file, 'a') as file:
                    line = f"{chain_type} took {total_time} seconds to construct.\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'extraction'):
            try:
                with open(self.log_file, 'a') as file:
                    line = f"Gadget Extraction took {total_time} seconds\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'num_dll'):
            num_dll = extra
            try:
                with open(self.log_file, 'a') as file:
                    line = f"Total DLLs {num_dll}\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'dll_name'):
            dll_name = extra
            try:
                with open(self.log_file, 'a') as file:
                    line = f"DLL: {dll_name}\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'failed_dll'):
            failed_dll = extra
            try:
                with open(self.log_file, 'a') as file:
                    line = f"\tExtraction FAILED ON: {failed_dll}\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'classification'):
            try:
                with open(self.log_file, 'a') as file:
                    line = f"Gadget Classification took {total_time} seconds\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'DLL_Extraction'):
            try:
                with open(self.log_file, 'a') as file:
                    line = f"DLL Extraction & Evaluation took {total_time} seconds\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'find_gadget'):
            gadget_type = extra
            try:
                with open(self.log_file, 'a') as file:
                    line = f"Running {gadget_type} took {total_time} seconds\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")
        elif (log_type == 'emu'):
            emu_type = extra
            try:
                with open(self.log_file, 'a') as file:
                    line = f"Running RopEMU:{emu_type} took {total_time} seconds\n"
                    file.write(line)
            except IOError as e:
                print(f"Error occured: {e}")