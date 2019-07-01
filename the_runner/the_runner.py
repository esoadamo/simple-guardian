from subprocess import Popen
from sys import argv, executable

RESTART_EXIT_CODE = 42  # if program exists with this code after enable_restart_on_runtime() was called, the restart
# of program is caused, instead of exiting


def enable_restart_on_runtime():
    """
    Running this function during startup will allow this program to be restarted by using runtime_restart() function
    :return: None
    """
    slave_identification = 'this_is_the_slave_of_the_runner'

    if argv[-1] != slave_identification:
        process = None
        try:
            while True:
                process = Popen([executable] + argv + [slave_identification])
                process.communicate()
                process.wait()
                r = process.returncode
                if r != RESTART_EXIT_CODE:
                    break
            exit(r)
        except KeyboardInterrupt:
            if process is not None:
                process.kill()
            print('^C received, shutting down master process')
            exit(0)
    del argv[-1]


def runtime_restart():
    """
    Restarts this script
    :return: None
    """
    exit(RESTART_EXIT_CODE)
