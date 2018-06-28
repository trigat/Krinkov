#######################################################################
#                       Krinkov
#
#             Simple SSH firewall for Unix/Linux.
#
#      Copyright (C) 2018, Josh M <trigat@protonmail.com>
#
#----------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#----------------------------------------------------------------------
#
# Krinkov uses TCP Wrapper to filter connections.
#
# --Monitors connection attempts and blacklists IP addresses
# after multiple connection attempts.
# Blacklist is removed after specified time limit.
#
# Optional port rotation setting allows you to auto change port #
# throughout the day.
#
#            INSTRUCTIONS
#  1. Adjust custom settings below.
#  2. Copy krinkov.py to /etc/krinkov.py
#  3. Create blank file:  /var/log/krinkov.log
#  4. Paste the below 2 lines at bottom of /etc/hosts.allow
#     Do not include # at beginning.
#
#  sshd : ALL : spawn /bin/echo "%a $(date)" >> /var/log/krinkov.log \
#  && python /etc/krinkov.py
#
#######################################################################

from datetime import datetime, date, time
import subprocess
import fileinput
import shutil
import sys
import re

########### Adjust Custom Settings ##############
#################################################

# Make sure you make this script executable.
# Example:
# chmod +x /etc/krinkov.py

# Login attempts allowed before ban:
login_attempts = 3

# Specified number of login_attempts must be made within
# this time for ban to kick in:
# (Number is in seconds.)
attempts_time = 90

# Specify seconds before ban expires:
ban_expire = 600

# Different Operating Systems may log datetime in different format
# Type the below command on command line to get datetime:
#                  echo $(date)

# Example:
# Fri   Jun   22   21:27:36   CDT   2018
#  1     2    3       4        5     6
#
# That would make date=3, time=4, and year=6

# Uncomment and use this for Debian 8.9:
#date_order = 3
#time_order = 4
#year_order = 6

# Uncomment and use this for Ubuntu 16.04:
# date_order may be 2 in different versions
date_order = 3
time_order = 4
year_order = 6

# Uncomment and use this for Solaris 11.3:
#date_order = 3
#time_order = 5
#year_order = 4

# *NOTE* If using Solaris, you'll have to enable TCP Wrappers by 
# typing the below command as root:
#
#          inetadm -M tcp_wrappers=TRUE

############# End Custom Settings ###############
#################################################

########## Port Rotation Settings ###############
#################################################

# If enabled, SSH port will change throughout the day.

# Set Allow_Port_Rotation to True to enable.
# Change to False to disable.

Allow_Port_Rotation = True
# *NOTE*
# Make sure you uncomment the "Port 22' line on your
# /etc/ssh/sshd_config file.

# Example: Once 6:00 AM comes, if someone attempts to log in,
# SSH will switch to your second port choice. (p2)

# Times are set in source code.

# Enter port numbers you want to use.  You can use a port more 
# than once.
p1 = "922"  #port will be active from 00:00 - 06:00 AM
p2 = "922"  #port will be active from 06:01 - 12:00 PM
p3 = "923"  #port will be active from 12:01 - 06:00 PM
p4 = "923"  #port will be active from 06:01 - 11:59 AM

# Program must start SSH daemon to change ports
# Make sure you uncomment the correct command for your OS:

# Linux uses "systemctl restart sshd"
#   So you use:
ssh_restart_cmd = ["systemctl", "restart", "sshd"]

# Solaris uses "svcadm restart ssh"
#   So you use:
# ssh_restart_cmd =  ["svcadm", "restart", "ssh"]

# FreeBSD uses "/etc/rc.d/sshd start"
#   So you use:
# ssh_restart_cmd =  ["/etc/rc.d/sshd", "start"]

######### End Port Rotation Settings ############
#################################################

subtract_one = login_attempts - 1
present = datetime.now()

def get_sec_short(time_str):
    h, m, s = time_str.split(':')
    return int(h) * 3600 + int(m) * 60 + int(s)

def ban_time_elapse(t1, t2):
    t1_dt = datetime(
        t1.year, t1.month, t1.day, t1.hour, t1.minute, t1.second)

    t2_dt = datetime(
        t2.year, t2.month, t2.day, t2.hour, t2.minute, t2.second)

    time_elapsed = t1_dt - t2_dt
    return time_elapsed

def clean_hosts():
    try:
        with open('/etc/hosts.allow', 'r') as f, open('/etc/hosts2.allow', 'w') as f2:
            # checks for line that starts with '###'
            reg = re.compile('###\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                             '.+(\d{4}-\d{2}-\d{2}\s\d{2}'
                             ':\d{2}:\d{2}.\d{0,})\s###')
            skipline = 0
            for line in f:
                if skipline:
                    skipline -= 1
                    continue  # Don't do anything with this line

                m = reg.match(line)
                if m:                # get date from line we grabbed
                    t2 = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f")
                    t1 = present
                    check_time = ban_time_elapse(t1, t2)
                    seconds_lapsed = get_sec_short(str(check_time))
                    print(seconds_lapsed)
                    if seconds_lapsed > ban_expire: # ban_expire is set by user
                        skipline = 2  # leave out this line & next
                    else:
                        print("Ban has not expired.")
                if not skipline:
                    f2.write(line) # unban by writing over lines
                    f2.close
        f.close
    except OSError as e:
        print (e)

    try:
        shutil.copy('/etc/hosts2.allow', '/etc/hosts.allow')
    except Error as err:
        errors.extend(err.args[0])

def update_hosts_allow(x1):
    try:
        with open('/etc/hosts.allow', 'r') as orig:
            data = orig.read()
        with open('/etc/hosts.allow', 'w') as mod:  # write line to ban IP address
            mod.write('### ' + x1 + ' banned @ ' + str(present) + ' ###\nsshd : ' + x1 \
                + ' : spawn /bin/echo "%a $(date)" >> /var/log/krinkov.log && python /etc/krinkov.py : DENY\n\n' + data)
    except OSError as e:
        print (e)
    clean_hosts()

def get_sec_long(time_str):  # converts date and time string to seconds
    y, d, h, m, s = time_str.split(':')
    return int(y) * 31536000 + int(d) * 86400 + int(h) * 3600 + int(m) * 60 + int(s)

def run_main():  # STARTING HERE
    try:
        logfile = open('/var/log/krinkov.log', 'r')
        line_number = dict()
        for index,line in enumerate(logfile,1):  # scan lines
            if line in ['\n', '\r\n']:  # Error Checking: if not enough lines in var .log
                print("Not enough IP addresses in log to compare.")
                clean_hosts()
                return
            if line:
                x1 = line.split()[0]  # if line, get IP address
                log_day  = line.split()[date_order]
                log_time = line.split()[time_order]  # This will already be in the format of hh:mm:ss
                log_year = line.split()[year_order]
            if x1 in line_number :  # if ip address on line
                line_number[x1].append((log_year + ":" + log_day.replace(",","") + ":" + log_time))
            else:                                             # .replace(",","") is ued for Solaris 11
                line_number[x1] = [(index,log_time)]

        # subtract_one number must be 1 less than login_attempts number
        if x1 in line_number and len(line_number.get(x1,None)) > subtract_one:
            #print("3 attmpts ago: " + line_number[x1][-login_attempts].__str__())
            old_time = (line_number[x1][-(login_attempts)].__str__())

            old_time_converted = get_sec_long(old_time)  # convert datetime string to seconds
            log_time_converted = get_sec_long(log_year + ":" + log_day.replace(",","") + ":" + log_time)

            time_difference = log_time_converted - old_time_converted   # difference between oldest allowed login attempt and newest
            # print(time_difference)

            print(x1 + ' connected ' + login_attempts.__str__() + ' times in ' \
                + time_difference.__str__() + " seconds.")

            # if login attempts are made within how many seconds?
            if time_difference < attempts_time:
                update_hosts_allow(x1)
            else:
                print('Not enough connection attempts made in specified time of ' \
                    + str(attempts_time) + ' seconds.')
                clean_hosts()
                pass

        else:
            print(x1 + ' - Not enough connection attempts to ban.')
            clean_hosts()  # check and clean allow.hosts 
        logfile.close
        
    except OSError as e:
        print (e)

run_main()

################# PORT ROTATION CODE BELOW ############################

def run_cmd_line():
    try:
        process = subprocess.Popen(ssh_restart_cmd, stdout=subprocess.PIPE)
        out, err = process.communicate()
        #print(out)
        print("Restarted SSH daemon.")
    except OSError:
        print("\nError when running SSH restart command.")

def replace(port_number, correct_port):
    for line in fileinput.input("/etc/ssh/sshd_config", inplace = 1):
        # open sshd_config and update port number
        print line.replace(port_number, str(correct_port)).rstrip()
        # added .rstrip() so that new lines are not created
    print("Updated port.")
    run_cmd_line()

def rotate_ssh_port(port_number):
    dt = datetime.now()

    # first port(p1) will be active at time ranging from 00:00 - 06:00 AM
    # (p2) port will be active from 06:01 - 12:00 PM
    t1 = [time(00,00), time(06,01), time(12,01), time(18,01)]
    t2 = [time(06,00), time(12,00), time(18,00), time(23,59)]
    user_port = [p1, p2, p3, p4]
    for x, y, z in zip(t1, t2, user_port):
        if x <= dt.time() <= y:
            print("Port should be: " + z)
            correct_port = z
            if port_number != z:  # z is the chosen port for that time of day
                replace(port_number, correct_port)
            else:
                print("\nNo change needed for the time.  Port is already " + correct_port + ".")

def check_ssh_port():
    p = "Port "  # search for string that contains 'Port XX'
    # make sure there is a space after to the word Port
    ssh_config = open("/etc/ssh/sshd_config")
    for line in ssh_config:
        if p in line:
            port_number = line[line.find(p)+len(p):].strip()
            print("Current port number: " + port_number)
            rotate_ssh_port(port_number)

# Enable Port Rotation
if Allow_Port_Rotation == True:
    check_ssh_port()
