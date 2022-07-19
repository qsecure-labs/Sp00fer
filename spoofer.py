import subprocess
import emailprotectionslib.spf as spf
import emailprotectionslib.dmarc as dmarc
from colorama import Fore, Back, Style
from prettytable import PrettyTable
import argparse
import json
import time
from smtplib import SMTPException
from smtplib import SMTPResponseException
import smtplib
from scapy.all import *
import os
import random
import string


#
# Current Verion: 1.3 
# Date Modified: 29/06/2022 
# Changes Performed: 	Added the Message-ID header in the email MIME headers.
#						The capture file gets delete if it already exists.
#
#
# Current Verion: 1.2 
# Date Modified: 31/05/2022 
# Changes Performed: 	Changed ehlo to helo because smtplib.sendmail() appended the massage size to the mail from: address 
#							If ehlo was used (ESMTP), it caused DMARC and SPF problems, especially with Sophos antispam.
#						Added the MailFrom and HeaderFrom fields in the results report.
#
#
# Current Verion: 1.1 
# Date Modified: 19/05/2022 
# Changes Performed: 	Reply-To and Return-Path headers were not included in the emails sent. Fixed it
# 			CLIENTEMAIL and CLIENTNAME were not replaced if found in replyTo or returnPath variables. Fixed it.
#

# colours declarations
def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))
def prLightPurple(skk): print("\033[94m {}\033[00m" .format(skk))
def prPurple(skk): print("\033[95m {}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))
def prLightGray(skk): print("\033[97m {}\033[00m" .format(skk))
def prBlack(skk): print("\033[98m {}\033[00m" .format(skk))



lightblue = "\033[1;36m"
blue = "\033[1;34m"
normal = "\033[0;00m"
red = "\033[1;31m"
white = "\033[1;37m"
green = "\033[1;32m"
BOLD = '\033[1m'
yellow = '\033[93m'

if os.name == 'nt':
    print("""        ________________
       /.,------------,.\\
      ///  .=^^^^^^^\__|\\\\       _______  _______   _____
      \\\   `------.    .//______ \   _  \ \   _  \_/ ____\___________
       `\\`--...._  `; //' \\____ \/  /_\  \/  /_\  \   __\/ __ \_  __ \\
         `\\.-,___;. //'   |  |_> >  \_/   \  \_/   \  | \  ___/|  | \/
           `\\-..- //'     |   __/ \_____  /\_____  /__|  \___  >__|
             `\\ //'       |__|          \/       \/          \/
               \"\" """)

    print("\n")

else:
    prRed("""   ________________
   /.,------------,.\\
  ///  .=^^^^^^^\__|\\\\       _______  _______   _____
  \\\   `------.    .//______ \   _  \ \   _  \_/ ____\___________
   `\\`--...._  `; //' \\____ \/  /_\  \/  /_\  \   __\/ __ \_  __ \\
     `\\.-,___;. //'   |  |_> >  \_/   \  \_/   \  | \  ___/|  | \/
       `\\-..- //'     |   __/ \_____  /\_____  /__|  \___  >__|
         `\\ //'       |__|          \/       \/          \/
           \"\" """)

    print("\n")


# Supported aguments declaration
parser = argparse.ArgumentParser()
if os.name == 'nt':
    requiredNamed = parser.add_argument_group('Required arguments')
else:
    requiredNamed = parser.add_argument_group(
        red + 'Required arguments' + normal)

requiredNamed.add_argument('-d', '--domain', action='store',
                           help='Domain to be tested. If only this argument is set, the tool will show the SPF and DMARC record for that domain.', required=True)
requiredNamed.add_argument('-j', '--json', action='store',
                           help='Path to the JSON file which includes the templates of the emails to be sent')
if os.name == 'nt':
    optionalargs = parser.add_argument_group('Optional arguments')
else:
    optionalargs = parser.add_argument_group(
        green + 'Optional arguments' + normal)
optionalargs.add_argument('-t', '--tester', action='store',
                          help='Tester\'s email address - It will be used in all the tests which require an external domain (i.e. outside the domain which is tested) ')
optionalargs.add_argument('-e', '--email', action='store',
                          help='Client email address - one valid email address from the domain to be tested')
optionalargs.add_argument('-s', '--server', action='store',
                          help='Mail server IP to be used')
optionalargs.add_argument('-p', '--port', action='store', default=25,
                          help='Mail server port to be used (default 25)')
optionalargs.add_argument('-l', '--delay', action='store', default=5,
                          help='Delay between emails - defaults to 5 seconds')
optionalargs.add_argument('-y', '--helo', action='store', default=5,
                          help='Domain to be used in the EHLO/HELO command')
if os.name == 'posix':
    optionalargs.add_argument('-c', '--pcap', action='store',
                              help='Detailed traffic capture of all the SMTP commands in a readable format. Provide the filename')

args = parser.parse_args()

# Check if the Results folder already exists. If not, create it
path = os.getcwd()
if os.path.exists(path + "/Results") == False:
    os.mkdir(path + "/Results")

# Create file to store the results
results_name = args.domain + ".txt"
file = open("Results/" + results_name, "a")

# Delete pcap file if it exists 
file_path = path + "/Results/capture.cap"
if os.path.exists(file_path) == True:
    os.remove(file_path)


# Fill the domain table
x = PrettyTable()
x.field_names = ["Domain"]
x.add_row([args.domain])
print(x)
if os.path.isfile('Results/' + results_name):
    file.write("\n\n")
file.write(str(x))

# if the domain argument is given, print the SPF and DMARC records of the domain
if (args.domain is not None):
    try:
        spf_record = spf.SpfRecord.from_domain(args.domain)
        if os.name == 'nt':
            print ("\nSPF Record: ")
            print (spf_record.record + "\n")
        else:
            prGreen("\n SPF Record: ")
            prCyan(spf_record.record + "\n")
        file.write("\n\nSPF Record: ")
        file.write(spf_record.record + "\n")
    except:
        if os.name == 'nt':
            print("No SPF record found\n")
        else:
            prCyan("No SPF record found\n")
        file.write("No SPF record found\n")

    try:
        dmarc_record = dmarc.DmarcRecord.from_domain(args.domain)
        file.write("\nDMARC Record: ")
        if os.name == 'nt':
            print("DMARC Record: ")
            print(dmarc_record.record + "\n")
        else:
            prGreen("DMARC Record: ")
            prCyan(dmarc_record.record + "\n")
        file.write(dmarc_record.record + "\n")
    except:
        if os.name == 'nt':
            print("No DMARC record found\n")
        else:
            prCyan("No DMARC record found\n")
        file.write("No DMARC record found\n")

# Generate the CLIENTNAME parameter to be replaced in the JSON file
if (args.email is not None):
    temp = args.email.split("@")
    clientname = temp[0]

# Start the capturing to save all the SMTP communications
if os.name == 'posix':
    if (args.pcap is not None):
        tcpd = subprocess.Popen(
            ['tcpdump', '-n', 'port ' + str(args.port), '-w', 'Results/capture.cap'])

# Make all the necessary replacements in the JSON file depending on the
# arguments given by the user
if (args.json is not None):
    with open(args.json) as f:
        data = json.load(f, strict=False)

    for i in list(range(len(data))):
        if(args.email is not None):
            data[i]['mailfrom'] = data[i]['mailfrom'].replace(
                'CLIENTEMAIL', args.email)
            data[i]['headerfrom'] = data[i]['headerfrom'].replace(
                'CLIENTEMAIL', args.email)
            data[i]['to'] = data[i]['to'].replace('CLIENTEMAIL', args.email)
            try:
                data[i]['returnPath'] = data[i]['returnPath'].replace(
                    'CLIENTEMAIL', args.email)
                data[i]['replyTo'] = data[i]['replyTo'].replace(
                    'CLIENTEMAIL', args.email)
            except:
                pass


            data[i]['mailfrom'] = data[i]['mailfrom'].replace(
                'CLIENTNAME', clientname)
            data[i]['headerfrom'] = data[i]['headerfrom'].replace(
                'CLIENTNAME', clientname)
            data[i]['to'] = data[i]['to'].replace('CLIENTNAME', clientname)
            try:
                data[i]['returnPath'] = data[i]['returnPath'].replace(
                    'CLIENTNAME', clientname)
                data[i]['replyTo'] = data[i]['replyTo'].replace(
                    'CLIENTNAME', clientname)
            except:
                pass


        if(args.tester is not None):
            data[i]['mailfrom'] = data[i]['mailfrom'].replace(
                'TESTERDOMAIN', args.tester)
            data[i]['headerfrom'] = data[i]['headerfrom'].replace(
                'TESTERDOMAIN', args.tester)
            data[i]['to'] = data[i]['to'].replace('TESTERDOMAIN', args.tester)
            try:
                data[i]['returnPath'] = data[i]['returnPath'].replace(
                    'TESTERDOMAIN', args.tester)
                data[i]['replyTo'] = data[i]['replyTo'].replace(
                    'TESTERDOMAIN', args.tester)
            except:
                pass

        if(args.domain is not None):
            data[i]['mailfrom'] = data[i]['mailfrom'].replace(
                'CLIENTDOMAIN', args.domain)
            data[i]['headerfrom'] = data[i]['headerfrom'].replace(
                'CLIENTDOMAIN', args.domain)
            data[i]['to'] = data[i]['to'].replace('CLIENTDOMAIN', args.domain)

        if(args.server is not None):
            data[i]['server'] = data[i]['server'].replace(
                'SERVERIP', args.server)

# Write the changes in the JSON file
    with open(args.json, 'w') as f:
        json.dump(data, f)

# Open the changed JSON file
    with open(args.json) as f:
        data_new = json.load(f, strict=False)

    x1 = PrettyTable()

# Generating the emails based on the JSON templates
    for i in list(range(len(data_new))):
        if("@" in data_new[i]["mailfrom"]):
            at_index = data_new[i]["mailfrom"].index("@")
            fromdomain = data_new[i]["mailfrom"][at_index:]
            messageID = '<' + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for k in range(48)) + fromdomain + '>'
        elif("@" in data_new[i]["headerfrom"]):
            at_index = data_new[i]["headerfrom"].index("@")
            fromdomain = data_new[i]["headerfrom"][at_index:]
            messageID = '<' + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for k in range(48)) + fromdomain + '>'
        else:
            messageID = '<' + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for k in range(48)) + '@' + ''.join(random.choice(string.ascii_lowercase) for l in range(10)) + '.com' + '>'
    
        if("replyTo" in data_new[i] and "returnPath" not in data_new[i]):
            message = f"""From: {data_new[i]["headerfrom"]}
To: {data_new[i]["to"]}
Reply-To: {data_new[i]["replyTo"]}
Subject: {data_new[i]["subject"]}
Message-ID: {messageID}

{data_new[i]["body"]}
"""
        elif("replyTo" not in data_new[i] and "returnPath" in data_new[i]):
            message = f"""From: {data_new[i]["headerfrom"]}
To: {data_new[i]["to"]}
Return-Path: {data_new[i]["returnPath"]}
Subject: {data_new[i]["subject"]}
Message-ID: {messageID}

{data_new[i]["body"]}
"""
        elif("replyTo" in data_new[i] and "returnPath" in data_new[i]):
            message = f"""From: {data_new[i]["headerfrom"]}
To: {data_new[i]["to"]}
Reply-To: {data_new[i]["replyTo"]}
Return-Path: {data_new[i]["returnPath"]}
Subject: {data_new[i]["subject"]}
Message-ID: {messageID}

{data_new[i]["body"]}
"""
        elif("replyTo" not in data_new[i] and "returnPath" not in data_new[i]):
            message = f"""From: {data_new[i]["headerfrom"]}
To: {data_new[i]["to"]}
Subject: {data_new[i]["subject"]}
Message-ID: {messageID}

{data_new[i]["body"]}
"""

        if os.name == 'nt':
            print("\nLIVE results - Scenario " + data_new[i]["scenario_no"])
        else:
            prGreen("\nLIVE results - Scenario " + data_new[i]["scenario_no"])

        try:
            # Attempt to send the emails; if there is an SMTP error it will throw an exception
            smtpObj = smtplib.SMTP(data_new[i]["server"], args.port)
            if args.helo is not None:
                smtpObj.helo(args.helo)
            smtpObj.sendmail(data_new[i]["mailfrom"],
                             data_new[i]["to"], message)
            if os.name == 'nt':
                print("Email successfully sent")
            else:
                prCyan("Email successfully sent")
            x1.field_names = ["No", "Result", "MailFrom", "HeaderFrom", "To", "Description"]
            x1.add_row([data_new[i]["scenario_no"],
                        "Sent", data_new[i]["mailfrom"], data_new[i]["headerfrom"], data_new[i]["to"], data_new[i]["comment"]])
            x1.align["Description"] = "l"
            print(x1)

        except SMTPException as e:
            if os.name == 'nt':
                print ("SMTP Error: ")
                print (e)
            else:
                print (red + "SMTP Error: ")
                prRed(e)
            x1.field_names = ["No", "Result", "MailFrom", "HeaderFrom", "To", "Description"]
            x1.add_row([data_new[i]["scenario_no"],
                        "Not sent", data_new[i]["mailfrom"], data_new[i]["headerfrom"], data_new[i]["to"], data_new[i]["comment"]])
            x1.align["Description"] = "l"
            print(x1)
        time.sleep(int(args.delay))

    print ("\n")
    if os.name == 'nt':
        print ("FINAL results:")
    else:
        prCyan("FINAL results:")
    x1.align["Description"] = "l"
    print(x1)
    file.write("\nFINAL Results\n")
    file.write(str(x1))
    file.close()

# fakeemail to fix the tcpdump which is not capturing the last few packets
# Ignore this one in your results if it is shown
    try:
        smtpObj = smtplib.SMTP(args.server, args.port)
        smtpObj.sendmail("fakeemail",
                         "fakeemail", "fakemessage")
    except:
        pass

else:
    if os.name == 'nt':
        print (
            "NOTE: For futher testing, you should provide a JSON file with the correct templates")
    else:
        prYellow(BOLD + "NOTE: " + normal + yellow +
                 "For futher testing, you should provide a JSON file with the correct templates")

# Use the PCAP file generated by tcpdump and present it in a readable format in an output TXT file
if os.name == 'posix':
    if (args.pcap is not None):
        f1 = open("Results/" + args.pcap, "a+")
        tcpd.send_signal(subprocess.signal.SIGTERM)
        packets = rdpcap('Results/capture.cap')
        i = 0
        j = 0
        while (i < len(packets)):
            try:
                data = packets[i][Raw].load
                src = packets[i][IP].src
                dst = packets[i][IP].dst
                data_string = str(data)
                data_string = data_string.replace('b\'', '')
                if "ehlo" in data_string or "helo" in data_string:
                    if (j + 1 <= len(data_new)):
                        f1.write("\n----------------------\n")
                        f1.write("     Scenario " +
                                 data_new[j]["scenario_no"] + "\n")
                        f1.write("----------------------\n")
                        j = j + 1
                if (j <= len(data_new)):
                    if str(dst) == args.server:
                        f1.write("CLIENT: ")
                    else:
                        f1.write("SERVER: ")
                    f1.write(data_string)
                    f1.write("\n")
            except:
                pass
            i = i + 1
        with open('Results/' + args.pcap, 'r') as fin:
            temp = fin.read().splitlines(True)
        with open('Results/' + args.pcap, 'w') as fout:
            fout.writelines(temp[2:])
        f1.close()
