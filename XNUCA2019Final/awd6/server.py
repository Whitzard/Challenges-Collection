import subprocess
import sys
import os
import random
import time
import signal
import re
from secret import *
TH = signal.getsignal(signal.SIGTERM)

def init():
    global dirname
    char_set = "XnucaCTF2019hAvefUN"
    dirname = "tmp_" + ''.join([random.choice(char_set) for _ in range(8)])
    os.mkdir(dirname)
    os.chdir(dirname)
    os.mkdir("flag")
    sys.stdout.write("initializing...\n")
    sys.stdout.flush()
    signal.signal(signal.SIGTERM, term_handler)
    signal.signal(signal.SIGALRM, alarm_handler)
    time.sleep(3)
    signal.alarm(30)

def read_data(fd):
    # data bigger than 4095 bytes should be unpacked into small ones due to Limits of STDIN buffer size
    buffer = ""
    char = fd.read(1)
    count = 8192
    while count and char != '#':
        if char in '0123456789abcdefABCDEF':
            buffer += char
        count -= 1
        char = fd.read(1)
    sys.stdout.write("Zip file recvied size %d\n" % (8192 - count))
    sys.stdout.flush()
    return buffer

def fini():
    global dirname
    signal.alarm(0)
    os.chdir("../")
    if os.path.exists(dirname):
        os.system("rm -r %s" % dirname)

def alarm_handler(signum, frame):
    sys.stdout.write("Time Out Be Quicker...\n")
    fini()
    exit(0)

def term_handler(signum, frame):
    global TH
    fini()
    signal.signal(signal.SIGTERM, TH)
    os.kill(os.getpid(), signal.SIGTERM)
    #signal.raise_signal(signal.SIGTERM)


if __name__ == "__main__":
    init()
    try:
        sys.stdout.write("Hex encoded zip file stream:\n")
        sys.stdout.flush()
        zip_data = read_data(sys.stdin)
        zip_data = zip_data.decode("hex")
        with open("punch", 'wb') as fw:
            fw.write(zip_data)
        proc = subprocess.Popen(["../vulnerable", "punch"], shell=False, stderr = subprocess.PIPE)
        time.sleep(3)
        proc.kill()
        returncode = proc.poll()
        if proc.returncode == 0xfa:
            if os.path.exists(os.path.join("flag", str(proc.pid))):
                with open(os.path.join("flag", str(proc.pid)), 'r') as fr:
                    token = fr.read()
                if token == FLAG_TOKEN:
                    with open(FLAG_PATH, 'rb') as fr:
                        flag = fr.read()
                    sys.stdout.write("Here is flag for hijacking to magic: %s\n" % flag)
                    sys.stdout.flush()
                os.system("rm %s" % os.path.join("flag", str(proc.pid)))
    finally:
        fini()
    exit(0)
