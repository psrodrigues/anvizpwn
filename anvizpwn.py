#!/usr/bin/env python
#
# # -*- coding: utf-8 -*-
import logging
import argparse
import TC_B

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

    parser.add_argument('--opendoor', dest='opendoor', action='store_true',
                        default=False,
                        help='Open door')
    args = parser.parse_args()


    #Started slecting arguments
    if(args.opendoor):
        TC_B.openDoor(args.ip[0],port=args.port,CH=args.CH)
