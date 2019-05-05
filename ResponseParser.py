import anvizpwn

# RESPONSES
ACK_SUCCESS = b"\x00"  # operation successful
ACK_FAIL = b"\x01"  # operation failed
ACK_FULL = b"\x04"  # user full
ACK_EMPTY = b"\x05"  # user empty
ACK_NO_USER = b"\x06"  # user not exist
ACK_TIME_OUT = b"\x08"  # capture timeout
ACK_USER_OCCUPIED = b"\x0A"  # user already exists
ACK_FINGER_OCCUPIED = b"\x0B"  # fingerprint already exists

def parseSuccess(response):
    #Analyse and report the response
    if(len(response)>7):
        raise Exception("Wrong Response format")
    if(response[3]== ACK_SUCCESS):
        print("[+]\tOperation Successfully")
    if (response[3] == ACK_FAIL):
        print("[-]\tOperation FAILED!")
    if (response[3] == ACK_FULL):
        print("[!]\tUser Full!")
    if (response[3] == ACK_EMPTY):
        print("[!]\tUser Empty")
    if (response[3] == ACK_NO_USER):
        print("[!]\tUser No User!")
    if (response[3] == ACK_TIME_OUT):
        print("[!]\tOperation Timed Out!")
    if (response[3] == ACK_USER_OCCUPIED):
        print("[!]\tUser Occupied!")
    if (response[3] == ACK_FINGER_OCCUPIED):
        print("[!]\tFingerprint already enroled!")