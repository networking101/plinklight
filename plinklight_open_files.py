#!/usr/bin/python

import logging
import pexpect
import sys
import os
import subprocess
import time
from optparse import OptionParser
from datetime import datetime


username = ''
password = ''
targetFile = []
csvpath = ''

pwd = os.getcwd()
dateName = datetime.utcnow().strftime("%Y-%m-%d_%H:%M:%S")
logFile = pwd + "/" + dateName

def main():
    usage = "Linux open file query over ssh"
    parser = OptionParser(usage = usage)
    
    # Username switch
    parser.add_option(
        "-u",
        "--username",
        help = "Username for the ssh login",
        action = "store",
        type = "string",
        dest = "username"
        )
    # Password switch
    parser.add_option(
        "-p",
        "--password",
        help = "Password for the ssh login",
        action = "store",
        type = "string",
        dest = "password"
        )
    # Target File switch
    parser.add_option(
        "-t",
        "--target-file",
        help = "Target file containing list of target IPs",
        action = "store",
        type = "string",
        dest = "targetfile"
        )
    # CSV Path switch
    parser.add_option(
        "-c",
        "--csv-path",
        help = "Path to save the CSV file",
        action = "store",
        type = "string",
        dest = "csvpath"
        )

    (options, args) = parser.parse_args()

    if not (options.targetfile or options.csvpath or options.username or options.password):
        parser.error('Missing require argument')

    username = options.username
    password = options.password
    targetFile = options.targetfile
    csvpath = options.csvpath
    
    Open_file(targetFile, username, password, csvpath)


def file_Logger(logLevel, output):
    
    logger = logging
    logging.basicConfig(level = logging.DEBUG,
                        format = '%(asctime)-12s: %(levelname)-8s %(message)s',
                        filename = logFile,
                        filemode = 'w'
                        )    
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
                        '%(asctime)-12s: %(levelname)-8s %(message)s'
                        )
    handler.setFormatter(formatter)

    logger.getLogger().addHandler(handler)
    if logLevel == 'debug':
        logger.debug(output)
    if logLevel == 'info':
        logger.info(output)
    if logLevel == 'error':
        logger.error(output)
    elif logLevel == 'warn':
        logger.warn(output)


def Open_file(targetFile, username, password, csvpath):

    # create final csv with compiled results
    header_saved = False
    header = 'COMMAND,PID,TID,USER,FD,TYPE,DEVICE,SIZE/OFF,NLINK,NODE,NAME,HOST\n'
    masterfile = csvpath + '/open_file_' + dateName + '.csv'
    
    with open(targetFile) as targets:
        for targ in targets:
    
    # Get start time for log file
            startTime = datetime.utcnow().strftime("%Y/%m/%d-%H:%M:%S-UTC")
            print startTime + "\tTarget:\t" + targ
    
    # Create ssh command
            ssh = 'ssh ' + username + '@' + targ
            print ssh
            p=pexpect.spawn(ssh)
            #print p.before
            ssh_newkey = 'Are you sure you want to continue connecting'
            i = p.expect([ssh_newkey,'password:',pexpect.EOF])

            if i==0:
	
	# Accept key if this is a new host
                print "Accepting Key\n"
                p.sendline('yes')
                i = p.expect([ssh_newkey,'password:',pexpect.EOF])
            
            if i==1:
		
	# Send password to the system
                print "Sending Password:"
                p.logfile = sys.stdout
                #print p.before
                p.sendline(password)
	
	# run command and save to file
                print "running ps\n"
		command = 'sudo lsof +L 2>/dev/null | tr -s \' \' | tr \' \' \',\' | awk \'{print $0",' + targ.rstrip() + '"}\' > kapow.txt'
                #print p.before
                p.sendline(command)
		p.delaybeforesend = 1
		if username != "root":
		    p.sendline(password)

	# Copy file back to MIP
                print '\nCopying file to MIP\n'
                homefile = csvpath + '/open_file_' + targ.rstrip() + '.csv'
                scp = 'scp ' + username + '@' + targ.rstrip() + ':./kapow.txt ' + homefile
                print scp + '\n'
		time.sleep(1)
                q=pexpect.spawn(scp)
                j = q.expect(['password:',pexpect.EOF])
		if j==0:
                        q.sendline(password)
                        print q.read()          #for some fucking reason you need this to scp
                        print 'File Transfer Complete'
               	elif i==1:
	                print "Timeout?"
        	        pass
                q.close()

	# Remove kapow file on remote host
		print "Removing kapow.txt\n"
		p.sendline('rm -f ./kapow.txt')
		
	# Close Session
                print "Exiting Session\n"
                p.sendline('exit')
                p.expect(pexpect.EOF)
                p.close()

	# Append results to master CSV
		with open(masterfile, 'ab') as fout:
		    with open(homefile) as fin:
			if os.stat(homefile).st_size > 0:
			    fin.next()
			if not header_saved:
			    fout.write(header)
			    header_saved = True
			for line in fin:
			    fout.write(line)
		#os.remove(homefile)

		print targ.rstrip() + ' complete!\n________________________________________________________________________________________________________\n\n'

            elif i==2:
                print "Timeout?"
                pass
	    #print p.before	

if __name__ == "__main__":
    main()
