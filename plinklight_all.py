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
dateName = datetime.utcnow().strftime("%Y-%m-%d_%H;%M;%S")
logFile = pwd + "/" + dateName

def main():
    usage = "Linux hunt over ssh"
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
    
    Enum_proc(targetFile, username, password, csvpath)


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


def Enum_proc(targetFile, username, password, csvpath):

    # create final csv with compiled results
    header_proc = '%CPU,GROUP,PPID,USER,COMMAND,PROCESS,RGROUP,NI,PID,PGID,ELAPSED,RUSER,TIME,TTY,VSZ,HOST\n'
    header_net = 'PROTOCOL,RECV-Q,SEND-Q,LOCAL ADDRESS,LOCAL PORT,FOREIGN ADDRESS,FOREIGN PORT,HOST,PID,PROGRAM,STATE\n'
    header_user = 'USER NAME,PASSWORD-X,UID,GID,FULL NAME,HOME DIR,SHELL,USER,PASSWORD,LAST CHANGED,MIN PASS CHANGE,MAX PASS CHANGE,WARN BEFORE PASS CHANGE,INACTIVE,ACCOUNT EXPIRE,TIME DISABLED,HOST\n'
    header_group = 'GROUP,PASSWORD,GID,GROUP LIST,HOST\n'
    header_cron = 'PROPERTIES,HARD LINKS,OWNER,GROUP,SIZE (B),TIME STAMP,FILE,HOST,INTERVAL\n'
    header_chkconfig = 'SERVICE,HALT,SINGLE USER MODE,MULTIUSER WITHOUT NFS,FULL MULTIUSER MODE,UNUSED,X11,REBOOT,HOST\n'
    header_logon = 'USER,PSEUDO TERMINAL,SOURCE,DAY,TIME STAMP,STATUS,HOST\n'
    masterfile_proc = csvpath + '/enum_proc_' + dateName + '.csv'
    masterfile_net = csvpath + '/enum_net_' + dateName + '.csv'
    masterfile_user = csvpath + '/users_' + dateName + '.csv'
    masterfile_group = csvpath + '/group_' + dateName + '.csv'
    masterfile_cron = csvpath + '/cron_' + dateName + '.csv'
    masterfile_chkconfig = csvpath + '/chkconfig_' + dateName + '.csv'
    masterfile_logon = csvpath + '/logon_' + dateName + '.csv'
    
    with open(masterfile_proc, 'ab') as fout:
        fout.write(header_proc)
    with open(masterfile_net, 'ab') as fout:
        fout.write(header_net)
    with open(masterfile_user, 'ab') as fout:
        fout.write(header_user)
    with open(masterfile_group, 'ab') as fout:
        fout.write(header_group)
    with open(masterfile_cron, 'ab') as fout:
        fout.write(header_cron)
    with open(masterfile_chkconfig, 'ab') as fout:
        fout.write(header_chkconfig)
    with open(masterfile_logon, 'ab') as fout:
        fout.write(header_logon)


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
		p.delaybeforesend = 1
	
	# run command and save to file
                print "running commands\n"
		command = 'sudo ps -Ao "%C,%G,%P,%U,%a,%c,%g,%n,%p,%r,%t,%u,%x,%y,%z" | awk \'{print $0",' + targ.rstrip() + '"}\' | grep -v %CPU | grep -v -i  "ps -Ao" | grep -v -i "awk {print \$0" > kapow_' + targ.rstrip() + '_proc.csv;sudo netstat -plantu | grep -v \"Active Internet connections\" | grep -v Proto | sed \'s/: /-/g\' | sed \'s/:://g\' | sed \'s/ \[/\[/g\' | awk \'{print $0"' + targ.rstrip() + '"}\' | awk \' { t=$6; $6=$8; $8=t; print; }\' | grep -v \'TIME_WAIT\'| tr -s \' \' | tr \' \' \',\' | tr \':\' \',\' | tr \'/\' \',\' > kapow_' + targ.rstrip() + '_net.csv;sudo cat /etc/passwd | tr \':\' \',\' > kapow_' + targ.rstrip() + '_user.csv;sudo cat /etc/shadow | tr \':\' \',\' | awk \'{print $0",' + targ.rstrip() + '"}\' > kapow_' + targ.rstrip() + '_shadow.csv;sudo cat /etc/group | tr \',\' \';\' | tr \':\' \',\' | awk \'{print $0",' + targ.rstrip() + '"}\' > kapow_' + targ.rstrip() + '_group.csv;ls -al /etc/cron.hourly | awk \'{print $0",' + targ.rstrip() + '"}\' | awk \'{print $0",hourly"}\' | tr -s \' \' | tr \' \' \',\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | grep -v \',\.\.,\' | grep -v \',\.,\' | grep -v \'total\' | cut -c 2- > kapow_' + targ.rstrip() + '_cron.csv; ls -al /etc/cron.daily | awk \'{print $0",' + targ.rstrip() + '"}\' | awk \'{print $0",daily"}\' | tr -s \' \' | tr \' \' \',\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | grep -v \',\.\.,\' | grep -v \',\.,\' | grep -v \'total\' | cut -c 2- >> kapow_' + targ.rstrip() + '_cron.csv; ls -al /etc/cron.weekly | awk \'{print $0",' + targ.rstrip() + '"}\' | awk \'{print $0",weekly"}\' | tr -s \' \' | tr \' \' \',\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | grep -v \',\.\.,\' | grep -v \',\.,\' | grep -v \'total\' | cut -c 2- >> kapow_' + targ.rstrip() + '_cron.csv; ls -al /etc/cron.monthly | awk \'{print $0",' + targ.rstrip() + '"}\' | awk \'{print $0",monthly"}\' | tr -s \' \' | tr \' \' \',\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | grep -v \',\.\.,\' | grep -v \',\.,\' | grep -v \'total\' | cut -c 2- >> kapow_' + targ.rstrip() + '_cron.csv;ls -al /etc/cron.d | awk \'{print $0",' + targ.rstrip() + '"}\' | awk \'{print $0",d"}\' | tr -s \' \' | tr \' \' \',\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | sed \'s/\(\([^,]*,\)\{5\}[^,]*\),/\\1-/g\' | grep -v \',\.\.,\' | grep -v \',\.,\' | grep -v \'total\' | cut -c 2- >> kapow_' + targ.rstrip() + '_cron.csv;sudo chkconfig | sed \'s/[[:space:]]\+/,/g\' | awk \'{print $0",' + targ.rstrip() + '"}\' > kapow_' + targ.rstrip() + '_chkconfig.csv;sudo last -f /var/run/utmp | grep -v reboot | awk \'{print $0"' + targ.rstrip() + '"}\' | grep \'\\n\'| grep -v "utmp begins" | tr -s \' \' | tr \' \' \',\' | sed \'s/\(\([^,]*,\)\{4\}[^,]*\),/\\1-/\' | sed \'s/\(\([^,]*,\)\{4\}[^,]*\),/\\1-/\' | sed \'s/still,logged,in/still logged in/g\' > kapow_' + targ.rstrip() + '_logon.csv'

		#print p.before
                p.sendline(command)
		p.delaybeforesend = 1
		if username != "root":
		    p.sendline(password)
		p.delaybeforesend = 1

	# Copy file back to MIP
                print '\nCopying file to MIP\n'
                homefile = csvpath + '/proc_' + targ.rstrip() + '.csv'
		scp = 'scp ' + username + '@' + targ.rstrip() + ':./kapow* ' + csvpath + '/'
                print scp + '\n'
                #append(homefile,'proc'
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
		p.sendline('rm -f ./kapow*')
		
	# Close Session
                print "Exiting Session\n"
                p.sendline('exit')
                p.expect(pexpect.EOF)
                p.close()

	# Append results to master CSV
		homefile_proc = csvpath + '/kapow_' + targ.rstrip() + '_proc.csv'
                homefile_net = csvpath + '/kapow_' + targ.rstrip() + '_net.csv'
                homefile_user = csvpath + '/kapow_' + targ.rstrip() + '_user.csv'
                homefile_shadow = csvpath + '/kapow_' + targ.rstrip() + '_shadow.csv'
		homefile_group = csvpath + '/kapow_' + targ.rstrip() + '_group.csv'
                homefile_cron = csvpath + '/kapow_' + targ.rstrip() + '_cron.csv'
		homefile_chkconfig = csvpath + '/kapow_' + targ.rstrip() + '_chkconfig.csv'
                homefile_logon = csvpath + '/kapow_' + targ.rstrip() + '_logon.csv'
		append(homefile_proc,masterfile_proc)
                append(homefile_net,masterfile_net)
                append2(homefile_user,homefile_shadow,masterfile_user)
                append(homefile_group,masterfile_group)
                append(homefile_cron,masterfile_cron)
                append(homefile_chkconfig,masterfile_chkconfig)
                append(homefile_logon,masterfile_logon)

		print targ.rstrip() + ' complete!\n________________________________________________________________________________________________________\n\n'

            elif i==2:
                print "Timeout?"
                pass
	    #print p.before	

	# Function to append data to master files
def append(homefile,masterfile):
    with open(masterfile, 'ab') as fout:
	with open(homefile) as fin:
	    for line in fin:
		fout.write(line)
    os.remove(homefile)

def append2(homefile_passwd,homefile_shadow,masterfile):
    with open(masterfile, 'ab') as fout, open(homefile_passwd) as passwd, open(homefile_shadow) as shadow:
                    for t in zip(passwd,shadow):
                        fout.write(','.join(x.strip() for x in t)+'\n')
    os.remove(homefile_passwd)
    os.remove(homefile_shadow)

if __name__ == "__main__":
    main()
