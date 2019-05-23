import time
import threading
from threading import Lock
import sys
import os
import TC_B

if len(sys.argv) < 3:
    print("[!] Usage: %s <thread_count> <input_file> <output_directory>", sys.argv[0])
    sys.exit(1)

def testip(i, cv, ip, outdir):
    outfile = outdir+"/"+ip+".txt"
    global active_threads
    cv.acquire()
    while not active_threads < max_threads:
        cv.wait()

    active_threads = active_threads+1
    # print("[%s] Thread: %d starting (active threads %d)" % (ip, i, active_threads))
    cv.release()

    # Call function
    try:
        # (preamble, deviceCode, ack, returnValue, size, data, crc) = TC_B.getDateOfDevice(ip, 5010, b"\x00\x00\x00\x00")
        (user_amount, fp_amount, password_amount, card_amount, all_record_amount, new_record_amount) = TC_B.getUserRecordsAmount(ip, 5010, b"\x00\x00\x00\x00")
        if user_amount:
            print("\n[%s] Success!! (%s)\n" % (ip, user_amount))
            f = open(outfile, "a+")
            f.write(user_amount)
            f.close()
    except Exception as e:
        # print("\n[%s] Error while writing response: %s" % (ip, e))
        a = 1
        # do nothing

    cv.acquire()
    # print("Thread: %d finishing (active threads %d)" % (i, active_threads))
    active_threads = active_threads-1
    cv.notifyAll()
    cv.release()

# Global variables
max_threads = 0
active_threads = 0
args = []
ip_list = []

with open(sys.argv[2], 'r') as f:
  for line in f:
    ip_list.append(line.strip())

os.system("mkdir " + sys.argv[3])

# main program
max_threads = int(sys.argv[1])
cv = threading.Condition()
for i in range(0,len(ip_list)):
    cv.acquire()
    while active_threads >= max_threads:
        cv.wait()
    cv.notifyAll()
    cv.release()
    args.append(i)
    t = threading.Thread(target=testip, args=(args[i], cv, ip_list[i], sys.argv[3]))
    t.start()
    # print("main loop %d" % i)
