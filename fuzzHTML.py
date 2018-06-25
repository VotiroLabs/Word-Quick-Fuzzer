import os
import sys
import subprocess
import logging
import Queue
import signal
import thread
import threading
import argparse
import shutil
import atexit
from datetime import datetime
from time import sleep


sys.path.insert(0, './ExtDepLibs')
#from domato import generator
#Import win32com.client and winappdbg
from PopUpKiller import PopUpKiller


try:
    import win32com.client, win32com
except Exception, e:
    logger.error('win32com.client could not be imported. Try installing it using `pip install pypiwin32`', exc_info=True)
    exit() 

try:
    from winappdbg import Crash,win32,Debug
except Exception, e:
    logger.error('winappdbg could not be imported. Try installing it using `pip install winappdbg`', exc_info=True)
    exit()
try:
    import autoit
except:
    print('[Error] pyautoit is not installed. Which is required to run this fuzzer (Error POPUp Killer). Install pyautoit First https://pypi.python.org/pypi/PyAutoIt/0.3')
    exit()
    

def setupLogger():
    logging.basicConfig()
    logger = logging.getLogger('logger')
    logger.setLevel(logging.INFO)
    return logger
    
    

threads = []
IMAGE_NAME = "WINWORD.EXE"
OFFICE_VERSION = "16"

if 'PROGRAMFILES(X86)' in os.environ:
    PROG_NAME = "C:\\Program Files (x86)\\Microsoft Office\\root\\Office{0}\\{1}".format(OFFICE_VERSION, IMAGE_NAME)
else:
    PROG_NAME = "C:\\Program Files\\Microsoft Office\\root\\Office{0}\\{1}".format(OFFICE_VERSION, IMAGE_NAME)

PROG_ARGUMENTS = "/q"
crash_dir = os.getcwd() + "\\HTML_crashes\\"
inputs_dir = os.getcwd() + "\\HTML_inputs\\"
wordFile = os.getcwd() + "\\includetext.docx"
refFile = os.getcwd() + "\\1.html"
number_of_files = 1000
delete_inputs = False
APP_RUN_TIME = 30
DEBUGGER = 'winappdbg'
exec_count = 0

#Start fuzzing by creating a symlink, update etc. Need Administrator rights
def symlink(source, link_name):
    if os.name == "nt":
        import ctypes
        csl = ctypes.windll.kernel32.CreateSymbolicLinkW
        csl.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
        csl.restype = ctypes.c_ubyte
        flags = 1 if os.path.isdir(source) else 0
        try:
            if csl(link_name, source.replace('/', '\\'), flags) == 0:
                raise ctypes.WinError()
        except Exception, e:
            logger.error('Could not create a symbolic link. please ensure Python has permissions to make symbolic links OR run the fuzzer with an administrator privileges', exc_info=True)
            exit()     
            
def DeleteOfficeHistorty():
    #Delete Office startup files (not in use).
		
    logger.debug('[+] Deleting Safe Mode Prompt Office History')
    s = 'REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Office\{0}.0\Word\Resiliency\StartupItems" /f'.format(OFFICE_VERSION)
    s = 'REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Office\{0}.0\Word\File MRU" /v "Item 1" /f'.format(OFFICE_VERSION)
    os.popen(s)   
        
def ForceKillOffice():
    '''
    In case debugger is unable to kill the half dead office process, we will try to kill it forcefully.
    '''
    try:
        logger.debug('[+]',datetime.now().strftime("%Y:%m:%d::%H:%M:%S"),'Forcefully Killing Office Application')
        os.popen('taskkill /F /IM {0} > NUL'.format(IMAGE_NAME))
    except:
        pass
        
def AccessViolationHandlerWINAPPDBG(event):
    '''
    Handle access violation while using winappdbg
    '''
    global curr_input
    code = event.get_event_code()
    if event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance():
        crash = Crash(event)
        crash.fetch_extra_data(event)
        details = crash.fullReport(bShowNotes=True)
        violation_addr = hex(crash.registers['Eip'])
        thetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        exe_name =  event.get_process().get_filename().split('\\')[-1]
        crashfilename = 'crash_'+'_'+ curr_input.split('fuzz-')[1] +'.'+curr_input.split('.')[-1]
        synfilename = crash_dir+exe_name+'\\'+ violation_addr +'\\'+crashfilename + '.txt'
        if not os.path.exists(crash_dir+exe_name):
            os.makedirs(crash_dir+exe_name)
        if not os.path.exists(crash_dir+exe_name+'\\'+violation_addr):
            os.makedirs(crash_dir+exe_name+'\\'+violation_addr)
        shutil.copyfile(curr_input,crash_dir+exe_name+'\\'+violation_addr+'\\'+curr_input.split('fuzz-')[1])
        logger.info('[+]',datetime.now().strftime("%Y:%m:%d::%H:%M:%S"),'BOOM!! APP Crashed :','Crash file Copied to ',(exe_name+'\\'+violation_addr+'\\'+crashfilename))
        syn = open(synfilename,'w')
        syn.write(details)
        syn.close()
        logger.debug('[+] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S")+' Killing half dead process')
        try:
            event.get_process().kill()
        except:
            ForceKillOffice()	
        
def StillRunningWINAPPDBG(proc):
    '''
    This function (run as thread) kill the process after user defined interval.(not in use)
    '''
    sleep(APP_RUN_TIME)
    try:
        proc.kill()
    except:
        ForceKillOffice()

def generateHTMLInputs(numOfInputs, queue, fuzzer_dir = inputs_dir):
    '''
        Generating numOfInputs HTML files using DOMATO generator.
        Output directory is fuzzer_dir
    '''
    logger.debug('[+] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S") + ' HTML Thread started..')
    if os.path.exists(fuzzer_dir):
        logger.debug('[+] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S") +' {0} exists, adding files to queue'.format(fuzzer_dir))
        for item in os.listdir(fuzzer_dir):
            queue.put('{0}\\{1}'.format(fuzzer_dir,item))
    else:
        logger.debug('[+] Creating ./{0} directory'.format(fuzzer_dir))
        os.mkdir(fuzzer_dir)
        subprocess.call(["python", "./ExtDepLibs/domato/generator.py", "--output_dir", fuzzer_dir, "--no_of_files", str(numOfInputs)])
        for item in os.listdir(fuzzer_dir):
            queue.put('{0}\\{1}'.format(fuzzer_dir,item))
      
def pretty_print(count, char):
    if count == 1:
        print  '0: {1}'.format(count,char),
    elif (count % 50 == 0):
        print
        print  '{0}: {1}'.format(count,char),
    else:
        print char,

def wordGuard():
    '''Watches from Word hangs caused by Fields.Update() '''
    
    while True:
        r = subprocess.check_output('tasklist /FI "IMAGENAME eq {0}" /FI "STATUS eq not responding"'.format(IMAGE_NAME))
        lines = [line.split() for line in subprocess.check_output("tasklist").splitlines()]
        for line in lines:
            if line== [] or line[0] == 'IMAGE' or line[0].startswith('='):
                continue
            else:
                if line[0] == 'INFO:':
                    continue
                else:
                    os.system("taskkill /f /im {0} > NUL".format(IMAGE_NAME))
                    break
                
        sleep(7)   

def launchWord(queue):

    global exec_count, curr_input, event
    
    fail_count = 0
    logger.debug('[+] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S") +' Word Thread started..')
    word = win32com.client.DispatchEx("word.Application")
    logger.debug('[+]',datetime.now().strftime("%Y:%m:%d::%H:%M:%S"),'Using debugger : ',DEBUGGER)
    #wordGuard_tid = thread.start_new_thread(wordGuard, ())
    cmd = [PROG_NAME, PROG_ARGUMENTS, wordFile]
    debug = Debug(AccessViolationHandlerWINAPPDBG, bKillOnExit = True )
    proc = debug.execv(cmd)
    debug.loop()
    
    while (fail_count < 10 and fail_count >= 0):
        try:
            filename = queue.get(False)
            curr_input = '{0}'.format(filename)
            exec_count += 1
            logger.debug('[+] Generating symlink to {0}'.format(curr_input))
            symlink(curr_input, refFile)#make symbolic link
            
            try:
                logger.debug('[+] Updating Word via COM')
                
                if (word.Selection.Fields.Update() == 0): #update document fields
                    pretty_print(exec_count,'.')

            except Exception as e:
                if e is None or not isinstance(e, tuple):      
                    pass
                try:
                    if 'The remote procedure call failed.' in e:
                        logger.debug('[!] We have a crash!')
                        pretty_print(exec_count,'!')
                        if not os.path.exists(crash_dir):
                            os.mkdir(crash_dir)
                        os.system("cp {0} {1}/{2} > NUL".format(curr_input, crash_dir, curr_input.split('\\')[1]))
                        fail_count = -1
                    else:
                        logger.debug('[?] We have a hang?')
                        pretty_print(exec_count,'?')
                        ForceKillOffice()
                        fail_count = -1
                except:
                    pass
            finally:
                logger.debug('[+] Removing symlink from {0}'.format(curr_input))
                queue.task_done()
                try:
                    os.remove(refFile)
                except:
                    pass
        except Queue.Empty:
            fail_count += 1
            continue
    try:
        word.Quit()
        ForceKillOffice()
        
    except:
        pass
        
def analyzeCrashes():
    global threads, curr_input
    
    if not os.path.exists(crash_dir): 
        logger.info('[!] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S") +' There are no crashing inputs to analyze!')
        return
    
    if len(threads) == 0:
        popup = PopUpKiller()
        popup_tid = thread.start_new_thread(popup.POPUpKillerThread, ())
        threads.append(popup_tid)
    
    
    for file in os.listdir(crash_dir):
        try:
            if file == "":
                continue
            curr_input = '{0}\\{1}'.format(crash_dir, file)
            logger.debug('[+] Generating symlink to {0}'.format(curr_input))
            symlink(curr_input, refFile)#make symbolic link
            cmd = [PROG_NAME, PROG_ARGUMENTS, wordFile]
            debug = Debug(AccessViolationHandlerWINAPPDBG, bKillOnExit = True )
            proc = debug.execv(cmd)
            wordGuard_tid = thread.start_new_thread(StillRunningWINAPPDBG, (proc,))
            threads.append(wordGuard_tid)
            debug.loop()
        except:
            pass
        finally:
            try:
                logger.debug('[+] Removing symlink from {0}'.format(curr_input))
                os.remove(refFile)
            except:
                pass
                
def startFuzzing():
    
    global threads, curr_input
    q = Queue.Queue()
    
    logger.info('[+] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S") +' Starting!')
    html_tid = generateHTMLInputs(number_of_files, q, fuzzer_dir=inputs_dir)
    popup = PopUpKiller()
    popup_tid = thread.start_new_thread(popup.POPUpKillerThread, ())
    threads.append(popup_tid)
    

    while not q.empty():
        ForceKillOffice()
        #DeleteOfficeHistorty()
        launchWord(q)
    if not os.path.exists(crash_dir):
        exit()
   
    analyzeCrashes()

@atexit.register
def cleanup(signum = None, frame = None):
  
  ForceKillOffice()
  if (delete_inputs and os.path.exists(inputs_dir)): shutil.rmtree(inputs_dir,False)
  if os.path.exists(refFile): os.remove(refFile)
  exit()
    
    
    
if __name__ == "__main__":
    banner = '''
                     
    $$\      $$\           $$$$$$$$\ 
    $$$\    $$$ |          $$  _____|
    $$$$\  $$$$ | $$$$$$\  $$ |      
    $$\$$\$$ $$ |$$  __$$\ $$$$$\    
    $$ \$$$  $$ |$$ /  $$ |$$  __|   
    $$ |\$  /$$ |$$ |  $$ |$$ |      
    $$ | \_/ $$ |\$$$$$$$ |$$ |      
    \__|     \__| \____$$ |\__|      
                       $$ |          
                       $$ |          
                       \__|          
                   
    MSWORD Quick Fields Fuzzing Framework.
	Author : Amit Dori (twitter.com/_AmitDori_)
		'''
     
    
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    print banner
    logger = setupLogger()
    parser = argparse.ArgumentParser(prog='HTMLfuzzer', description="Fuzzing Word INCLUDETEXT Field HTML capabilities")
    parser.add_argument("operation", choices=['analyze','fuzz'], help="Operation mode: analyze or fuzz")
    parser.add_argument("-w", "--word-file", help="Name of Word File to use")
    parser.add_argument("-r", "--ref-file", help="Name of Symbolic link file to use")
    parser.add_argument("-n", "--number-of-files", help="Number of HTML files to generate", type=int)
    parser.add_argument("-i","--inputs-dir", help="Directory to save generate HTML files into")
    parser.add_argument("-o","--output-dir", help="Directory to save crashing HTML files")
    parser.add_argument("-v","--verbose", help="More info", action="store_true")
    parser.add_argument("-d","--delete-arguments",help="Delete generated HTML files when done", action="store_true")
    args = parser.parse_args()
    
    if args.word_file: wordFile = args.word_file
    if args.ref_file: refFile = args.ref_file
    if args.number_of_files: number_of_files = args.number_of_files
    if args.inputs_dir: inputs_dir = args.inputs_dir
    if args.output_dir: crash_dir = args.output_dir
    if args.verbose: logger.setLevel(logging.DEBUG)
    if args.delete_arguments: delete_inputs = True
    
    if args.operation == "fuzz":
        if os.path.exists(refFile): os.remove(refFile)
        startFuzzing()
    elif args.operation == "analyze":
        analyzeCrashes()
    cleanup()

        