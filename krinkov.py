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
# It Monitors connection attempts and blacklists IP addresses
# after multiple connection attempts.
# The blacklist is removed after specified time limit.
#
# To unban yourself after being blacklisted, you will have to 
# attempt to log in twice after blacklist has expired.
#
# Optional port rotation setting allows you to auto change port #
# throughout the day.
#
#            INSTRUCTIONS
#  1. Adjust custom settings below.
#  2. Copy krinkov.py to /etc/krinkov.py
#  3. Create blank log file:  /var/log/krinkov.log
#  4. Paste the below 2 lines at bottom of /etc/hosts.allow
#     Do not include # at beginning.
#
#  sshd : ALL : spawn /bin/echo "%a $(date)" >> /var/log/krinkov.log \
#  && python /etc/krinkov.py
#
# Each time someone attempts to connect via SSH, their information is
# stored in krinkov.log and this krinkov.py script is executed.
#
#######################################################################

from datetime import datetime, date, time
import subprocess
import fileinput
import shutil
import sys
import os
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

# Make sure your date and time format match properly.
# These defaults will usually work...

# Uncomment and use this for Debian 8.9:
#month_ = 2
#date_  = 3
#time_  = 4
#year_  = 6

# Uncomment and use this for Ubuntu 16.04:
# date_order may be 2 in different versions
month_ = 2
date_  = 3
time_  = 4
year_  = 6

# Uncomment and use this for Solaris 11.3:
#month_ = 2
#date_  = 3
#time_  = 5
#year_  = 4

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
                        print("Ban of " + str(ban_expire) + " seconds has not expired.")
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

def remove_last_line(logfile):
    # remove the last line in file we opened
    # the line will be replaced with new line later
    logfile.seek(0, os.SEEK_END)
    while logfile.tell() and logfile.read(1) != '\n':
        logfile.seek(-2, os.SEEK_CUR)
    logfile.truncate()

def get_sec_long(time_str):  # converts date and time string to seconds
    y, mo, d, h, m, s = time_str.split(':')
    return int(y) * 31536000 + int(mo) * 2592000 + int(d) * 86400 + int(h) * 3600 + int(m) * 60 + int(s)

def run_main():  # STARTING HERE
    # This function first grabs the last line entry in the log.
    # It converts time to 24 hour format and removes the word "AM" or "PM".
    # It then starts the function over and verifies if the format is correct.
    # If format is correct, it grabs 2 lines to compare the times.
    # One line will be the last in the file.  The other will be the line specified
    # by the user.
    # Example:
    # If user set 'login_attempts = 3', the 3rd from last line will be used.
    try:
        logfile = open('/var/log/krinkov.log', 'r+')
        line_number = dict()
        for index,line in enumerate(logfile,1):  # scan lines
            if line in ['\n', '\r\n']:  # Error Checking: if not enough lines in var .log
                print("Not enough IP addresses in log to compare.")
                clean_hosts()
                return
            if line:
                x1 = line.split()[0]  # if line, get IP address

                # Need to convert month text to integer.
                # Solaris and other OS may spell out the entire month.
                # Linux abbreviates the month.  Just in case, only grab
                # the first 3 letters so we can use strptime.
                grab_month = line.split()[month_]
                conv_month_to_string = datetime.strptime(grab_month[:3], '%b').month

                log_month = str(conv_month_to_string)
                log_day  = line.split()[date_]
                log_time = line.split()[time_]  # This will already be in the format of hh:mm:ss
                log_year = line.split()[year_]

            # if IP on line, return the year, day, time
            # else if key(IP) is not available, list the year, day, time anyways
            line_number[x1] = line_number.get(x1, []) + [log_year + ":" + log_month + ":" + log_day.replace(",","") + ":" + log_time]

        if "PM" in line and log_time[:2] != "12":
            log_time_int = int(log_time[:2]) # change to integer
            hour_24 = (log_time_int + 12)    # add 12
            mil_time = log_time.replace(log_time[:2], str(hour_24))
            log_time_24 = line.replace(log_time, mil_time).replace("PM", "")
            print(line.replace(log_time, mil_time)).replace("PM", "")

            # remove the last line in file we opened up top
            # line is going to be replaced with new line
            remove_last_line(logfile)

            # update line with 24 hours time and remove "PM"
            print("Removed last line in log")
            with open("/var/log/krinkov.log", "a") as f:  # open local log for write
                f.write(line.replace(log_time, mil_time).replace("PM", ""))
                f.close()
            run_main()  # then start over
        # if 12:00 AM, convert to 00:00
        # don't add 12 if it's already 12 PM
        elif "AM" in line and log_time[:2] == "12":
            mil_time = log_time.replace(log_time[:2], "00")
            log_time_24 = line.replace(log_time, mil_time).replace("AM", "")
            print(line.replace(log_time, mil_time)).replace("AM", "")

            # remove the last line in file we opened up top
            # line is going to be replaced with new line
            remove_last_line(logfile)

            # update line with 24 hours time and remove "AM"
            print("Removed last line in log")
            with open("/var/log/krinkov.log", "a") as f:  # open local log for write
                f.write(line.replace(log_time, mil_time).replace("AM", ""))
                f.close() 
            run_main()
        elif "AM" in line or "PM" in line:  # make sure AM/PM is not in line
            remove_last_line(logfile)
            print("Removed AM/PM")
            with open("/var/log/krinkov.log", "a") as f:  # open local log for write
                f.write(line.replace("AM", "").replace("PM", ""))
                f.close() 
            run_main()
        else:
            # once line is formatted properly, run the below:
            # subtract_one number must be 1 less than login_attempts number
            if x1 in line_number and len(line_number.get(x1,None)) > subtract_one:
                old_time = (line_number[x1][-login_attempts])
                old_time_converted = get_sec_long(old_time)  # convert datetime string to seconds
                log_time_converted = get_sec_long(log_year + ":" + log_month + ":" +log_day.replace(",","") + ":" + log_time)
                # if the date time format has any commas, remove them with replace()
                time_difference = log_time_converted - old_time_converted   # difference between oldest allowed login attempt and newest
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
                clean_hosts()  # remove this line if you don't want to do anything until
                               # set login_attempts have been met
            logfile.close

    except (IOError, OSError) as e:
        print("\nMake sure log file exists.  " + str(e) + "\n")
    except:
        print("\nLog may not contain any data.")
        print("Or date and time format may be set up incorrectly.")
        print("Adjust settings at top of source.\n")

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
