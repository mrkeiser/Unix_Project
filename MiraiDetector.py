#
# Name: MiraiDetector.py
# Decription: scans a Linux system for malware in the Mirai family, indicates
#     yes or no to if a malware sample has been found.
#     Has flags to scan a specific directory, identify a malware family, print
#     the file path of the malware, and take the hash of the possible malware
#     samples found (for use w/ VT).
# Date Revised: 04/15/2018
#

#
# IMPORT STATEMENTS
#

import os
import sys
import argparse

# PARSER FOR COMMAND LINE ARGUMENTS
# Note: flags may be conditional to each other (i.e. if malware is found, only then will the path and/or hash be printed

parser = argparse.ArgumentParser(description='flags for MiraiDetector tool, which helps in the identification of Mirai malware on a Linux system.')
parser.add_argument('-d', nargs='1', help='directory to scan')
parser.add_argument('-p', help='print the file path of the malware')
parser.add_argument('-th', help='take hash of the malware'))
args = parser.parse_args()

#
# FUNCTIONS
#

# function: scan
# desc: scans file system (root '/' directory by default)
# args: df - directory flag included in program run
# return: 

def scan():


# function: flags
# desc: a series of conditionals as to when to call parser
# args: argv[] - the user-given command line arguments 
# return: 

def flags():
	

# function: main()
# desc: main program
# args: argv[] - an array of user-defined command-lne input
# return: None

def main(argv[]):
    count = # length of arguments on command line

if __name__=="__main__":
    main()
