#!/usr/bin/python

import logging
import pexpect
import sys
import os
import subprocess
import time
from optparse import OptionParser
from datetime import datetime


username = '' #'mcdaniec'
password = '' #'Th1$1$th3CRdr@v3'
targetFile = [] #['131.7.235.78']
csvpath = ''

pwd = os.getcwd()
dateName = datetime.utcnow().strftime("%Y-%m-%d_%H:%M:%S")
logFile = pwd + "/" + dateName

def main():
    usage = "Linux user query over ssh"
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
    
    Enum_user(targetFile, username, password, csvpath)


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
        liogger.warn(output)


def Enum_user(targetFile, username, password, csvpath):

    # create final csv with compiled results
    header_saved = False
    header = 'USER NAME,PASSWORD-X,UID,GID,FULL NAME,HOME DIR,SHELL,USER,PASSWORD,LAST CHANGED,MIN PASS CHANGE,MAX PASS CHANGE,WARN BEFORE PASS CHANGE,INACTIVE,ACCOUNT EXPIRE,TIME DISABLED,HOST\n'
    masterfile = csvpath + '/user_' + dateName + '.csv'

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
                print "Accepting Key"
                p.sendline('yes')
                i = p.expect([ssh_newkey,'password:',pexpect.EOF])
            
            if i==1:
		
	# Send password to the system
                print "Sending Password"
                p.logfile = sys.stdout
                #print p.before
                p.sendline(password)
		p.delaybeforesend = 1
	
	# run command and save to file
                print "running ps"
		command = 'sudo cat /etc/passwd | tr \':\' \',\' > kapow_' + targ.rstrip() + '_passwd.csv;sudo cat /etc/shadow | tr \':\' \',\' | awk \'{print $0",' + targ.rstrip() + '"}\' > kapow_' + targ.rstrip() + '_shadow.csv'
                #print p.before
                p.sendline(command)
		p.delaybeforesend = 1
		if username != "root":
		    p.sendline(password)
		p.delaybeforesend = 1

	# Copy file back to MIP
                print '\nCopying file to MIP\n'
                homefile_passwd = csvpath + '/kapow_' + targ.rstrip() + '_passwd.csv'
                homefile_shadow = csvpath + '/kapow_' + targ.rstrip() + '_shadow.csv'
                scp = 'scp ' + username + '@' + targ.rstrip() + ':./kapow* ' + csvpath + '/'
                print scp + '\n'
		time.sleep(1)
                q=pexpect.spawn(scp)
                j = q.expect(['password:',pexpect.EOF])
                if j==0:
                        q.sendline(password)
                        print q.read()          #for some fucking reason you need this to scp
                        print 'File Transfer Complete'
                elif i==1:
                        print 'Timeout?'
			pass
                q.close()

	# Remove kapow file on remote host
                print "Removing kapow.txt\n"
                #p.sendline('rm -f kapow*')

	# Close Session
                print "Exiting Session"
                p.sendline('exit')
                p.expect(pexpect.EOF)
                p.close()

	# Append results to master CSV
		with open(masterfile, 'ab') as fout, open(homefile_passwd) as passwd, open(homefile_shadow) as shadow:
		    for t in zip(passwd,shadow):
			fout.write(','.join(x.strip() for x in t)+'\n')
		os.remove(homefile_passwd)
		os.remove(homefile_shadow)

		print targ.rstrip() + ' complete!\n________________________________________________________________________________________________________\n\n'

            elif i==2:
                print "Timeout?"
                pass
	    #print p.before	

if __name__ == "__main__":
    main()
