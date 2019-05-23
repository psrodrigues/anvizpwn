#!/usr/bin/env python
#
# # -*- coding: utf-8 -*-
import logging
import argparse
import TC_B
import ResponseParser

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
    parser.add_argument('ip', metavar='IP', type=str, nargs=1,
                        help='IP Address of the endpoint')
    parser.add_argument('--port', dest='port',
                        type=int, default=5010, nargs='?',
                        help='Management Port of the device')
    parser.add_argument('--channel', dest='CH',
                        type=str, default=b"\x00\x00\x00\x00", nargs='?',
                        help='Channel or Device Identification')
    parser.add_argument('--timeout', dest='timeout',
                        type=int, default=5, nargs='?',
                        help='Time out value')

    parser.add_argument('--config', dest='config', action='store_true',
                        default=False,
                        help='Get config')

    parser.add_argument('--opendoor', dest='opendoor', action='store_true',
                        default=False,
                        help='Open door')

    parser.add_argument('--date', dest='date', action='store_true',
                        default=False,
                        help='Get Date from the device')

    parser.add_argument('--network', dest='network', action='store_true',
                        default=False,
                        help='Get Network Information from the device')

    parser.add_argument('--userrecords', dest='userrecords', action='store_true',
                        default=False,
                        help='Get User records stored on the device')

    parser.add_argument('--useramount', dest='useramount', action='store_true',
                        default=False,
                        help='Get just amount of user records stored on the device')

    parser.add_argument('--factoryinfocode', dest='factoryinfocode', action='store_true',
                        default=False,
                        help='Get Factory information code')

    parser.add_argument('--inituserdata', dest='inituserdata', action='store_true',
                        default=False,
                        help='WARNING! This WILL ERASE data. Initialize users data')

    parser.add_argument('--initsystem', dest='initsystem', action='store_true',
                        default=False,
                        help='WARNING! This WILL ERASE data. Initialize system')

    parser.add_argument('--schedulebell', dest='schedualebell', action='store_true',
                        default=False,
                        help='Get Schedule bell data from device')

    parser.add_argument('--messageheaders', dest='messageheaders', action='store_true',
                        default=False,
                        help='Get Headers of messages stored in the device')

    parser.add_argument('--statemessage', dest='statemessage', action='store_true',
                        default=False,
                        help='Get state message data from device')

    parser.add_argument('--devicecapacity', dest='devicecapacity', action='store_true',
                        default=False,
                        help='Get device capacity from device')

    parser.add_argument('--commid', dest='commid', action='store_true',
                        default=False,
                        help='Get comunication ID of the device')

    parser.add_argument('--clearadmin', dest='clearadmin', action='store_true',
                        default=False,
                        help='Clear administrator flag for the device. May impact on the manageability of the device')

    parser.add_argument('--random', dest='random', action='store_true',
                        default=False,
                        help='Get random number from the device')

    parser.add_argument('--serialnumber', dest='serialnumber', action='store_true',
                        default=False,
                        help='Get serial number from the device')

    parser.add_argument('--specialstate', dest='specialstate', action='store_true',
                        default=False,
                        help='Get special state data from device')

    parser.add_argument('--photoamount', dest='photoamount', action='store_true',
                        default=False,
                        help='Get amount of photos stored in the device')

    parser.add_argument('--admincredentials', dest='admincredentials', action='store_true',
                        default=False,
                        help='Get administrator credentials (password/card number) from the device')

    parser.add_argument('--daylight', dest='daylight', action='store_true',
                        default=False,
                        help='Get daylight settings from the device')

    parser.add_argument('--languages', dest='languages', action='store_true',
                        default=False,
                        help='Get languages available on the device')

    parser.add_argument('--gprs', dest='gprs', action='store_true',
                        default=False,
                        help='Get GPRS settings from the device')

    parser.add_argument('--deviceextended', dest='deviceextended', action='store_true',
                        default=False,
                        help='Get device extended information')

    parser.add_argument('--cardinfo', dest='cardinfo', action='store_true',
                        default=False,
                        help='Get punchcard info from T5S devices')

    parser.add_argument('--dos', dest='dos', action='store_true',
                        default=False,
                        help='Cause a denial of service (Not implemented yet)')

    parser.add_argument('--devices', dest='devices', action='store_true',
                        default=False,
                        help='Search for devices in the network')

    args = parser.parse_args()

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
