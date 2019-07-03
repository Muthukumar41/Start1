import os
import re
import signal
import subprocess
import sys
import threading
from datetime import datetime
from time import sleep

import xlwt
import yaml
from xlwt import Workbook


class Condn:
    def __init__(self, var_one, if_yes_show, if_yes_cmd):
        if var_one:
            self.show = if_yes_show
            self.cmd = if_yes_cmd
        else:
            self.show = self.cmd = ''

def sub_process(cmd):
    try:
        output = subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
        return output
    except subprocess.CalledProcessError as e:
        #raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
        print("\nERROR\n".center(55,'-')+"\ncommand\t\t: '{}'\nError code\t: {}\nOutput\t\t: '{}'\n\nScanning again . . .".format(e.cmd, e.returncode, e.output))
        return 'repeat'
def signal_func(sig, frame):
    print("\n *\n  **\n   *** You Pressed Ctrl+C..!  Code Exited\n")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_func)


def ping_func():
    os.system('mkdir %s/traffic/logs/Ping 2>/dev/null'%(pwd_path))
    os.chdir("%s/traffic/logs/Ping"%(pwd_path))
    for iteration in range(0,(int(no_of_clients))):
        if iteration == int(no_of_clients)-1:
            print("\nPing process is running. . .\n")
            cmd1 = "ping %s %s -I wifi%s_%s %s %s >> ping_file_%s.txt 2>ping_file_%s.txt "%(ping_no_of_packets_class.cmd, ping_each_packet_interval_class.cmd, group_number, iteration, ping_destination, ping_run_time_class.cmd, iteration, iteration)
            trash1 = subprocess.check_output(cmd1, shell=True)
            print("\nPing process completed\n")
        else:
            cmd1 = "ping %s %s -I wifi%s_%s %s %s >> ping_file_%s.txt 2>ping_file_%s.txt &"%(ping_no_of_packets_class.cmd, ping_each_packet_interval_class.cmd, group_number, iteration, ping_destination, ping_run_time_class.cmd, iteration, iteration)
            os.system(cmd1)
    sleep(2)
    print("\nPing Process Finished~~~~~~~~#\n")
    wb_ping = Workbook()
    sheet_ping = wb_ping.add_sheet('Sheet 1', cell_overwrite_ok=True)
    bold_style = xlwt.easyxf('font: bold 1, color blue;')
    sheet_ping.write(0, 0, 'Interface name', bold_style)
    sheet_ping.write(0, 1, 'Packets Transmitted', bold_style)
    sheet_ping.write(0, 2, 'Packet Received', bold_style)
    sheet_ping.write(0, 3, 'Packet Loss', bold_style)
    sheet_ping.write(0, 4, 'Time', bold_style)
    sheet_ping.write(0, 5, 'Min Connecting time', bold_style)
    sheet_ping.write(0, 6, 'Max Connecting time', bold_style)
    for iteration in range(int(no_of_clients)):
        cmd1 = "tail -2 ping_file_%s.txt" % (iteration)
        ping_result = subprocess.check_output(cmd1, shell=True)
        ping_result = ping_result.strip('\n').split('\n')
        ping_result_list = ping_result[-2].split()
        ping_min_time = ping_result[-1].split()[3].split('/')[0]
        ping_max_time = ping_result[-1].split()[3].split('/')[2]
        print("\nInterface wifi%s_%s - %s"%(group_number, iteration, ping_result_list))
        Interface_name = "wifi%s_%s" % (group_number, iteration)
        sheet_ping.write(iteration+1, 0, Interface_name)
        sheet_ping.write(iteration+1, 1, ping_result_list[0])
        sheet_ping.write(iteration+1, 2, ping_result_list[3])
        sheet_ping.write(iteration+1, 3, ping_result_list[5])
        sheet_ping.write(iteration+1, 4, ping_result_list[9])
        sheet_ping.write(iteration+1, 5, ping_min_time)
        sheet_ping.write(iteration+1, 6, ping_max_time)
    wb_ping.save('../../Results/ping_result.xls')
    print("\nPing Traffic Generated and result saved in ping_result.xls file\n")
    # cmd1 = "rm ping_file*"
    # os.system(cmd1)

def iperf_func():
    os.system('mkdir %s/traffic/logs/iperf 2>/dev/null'%(pwd_path))
    os.chdir("%s/traffic/logs/iperf"%(pwd_path))
    for iteration in range(0, int(no_of_clients)):
        cmd1 = "ip addr list wifi%s_%s | grep 'inet ' | awk '{print $2}'| cut -d'/' -f1" % (group_number, iteration)
        ip = subprocess.check_output(cmd1, shell=True)
        ip = ip.strip('\n')
        if iteration == int(no_of_clients)-1:
            print("\nIperf process is running. . .\n")
            cmd1 = "iperf -c {0} -B {1}{2}{3}{4}{5}{6}{7}{8}{9} >> iperf_file_{10}.txt 2>iperf_file_{11}.txt".format(iperf_server, ip, iperf_packets_cmd, iperf_time_or_data_cmd, iperf_media_cmd, iperf_streams_class.cmd, iperf_port_number_class.cmd, iperf_bandwidth_class.cmd, iperf_window_size_class.cmd, iperf_buffer_size_class.cmd, iteration, iteration)
            # print("\n%s -- %s\n"%(iteration, cmd1))
            trash2 = subprocess.check_output(cmd1, shell=True)
            print("\nIperf process completed\n")
        else:
            cmd1 = "iperf -c {0} -B {1}{2}{3}{4}{5}{6}{7}{8}{9} >> iperf_file_{10}.txt 2>iperf_file_{11}.txt &".format(iperf_server, ip, iperf_packets_cmd, iperf_time_or_data_cmd, iperf_media_cmd, iperf_streams_class.cmd, iperf_port_number_class.cmd, iperf_bandwidth_class.cmd, iperf_window_size_class.cmd, iperf_buffer_size_class.cmd, iteration, iteration)
            # print("\n%s -- %s\n"%(iteration, cmd1))
            os.system(cmd1)
            sleep(0.2)
    while 1 :
        cmd1 = "ps -ef | grep -w iperf | wc -l"
        iperf_end_flag = subprocess.check_output(cmd1, shell=True)
        iperf_end_flag = iperf_end_flag.strip('\n')
        # print ("\nIperf -- %s\n"%(iperf_end_flag))
        if iperf_end_flag == '2':
            break
    print("\nIperf Process Finished~~~~~~~~#\n")
    wb_iperf = Workbook()
    sheet_iperf = wb_iperf.add_sheet('Sheet 1', cell_overwrite_ok=True)
    bold_style = xlwt.easyxf('font: bold 1, color blue;')
    sheet_iperf.write(0, 0, 'Interface name', bold_style)
    sheet_iperf.write(0, 1, 'Time', bold_style)
    sheet_iperf.write(0, 2, 'Data Transfer', bold_style)
    sheet_iperf.write(0, 3, 'Bandwidth', bold_style)
    print("\nInterface name\tTime\t\tData Transfer\tBandwidth")
    sleep(2)
    for iteration in range(0, int(no_of_clients)):
        if iperf_packets == 'TCP':
            cmd1 = "tail -1 iperf_file_%s.txt"%(iteration)
        else:
            cmd1 = "tail -2 iperf_file_%s.txt | head -1"%(iteration)
        iperf_result = subprocess.check_output(cmd1, shell=True)
        # print("\nIperf result list - %s\n"%(iperf_result))
        iperf_result_list = iperf_result.split()[2:]
        iperf_result_time = iperf_result_list[0].split('-')[1] + ' ' + iperf_result_list[1]
        iperf_result_data = iperf_result_list[2] + ' ' + iperf_result_list[3]
        iperf_result_bandwidth = iperf_result_list[4] + ' ' + iperf_result_list[5]
        print("wifi%s_%s\t\t%s\t%s\t%s"%(group_number, iteration, iperf_result_time, iperf_result_data, iperf_result_bandwidth))
        Interface_name = "wifi%s_%s" % (group_number, iteration)
        sheet_iperf.write(iteration+1, 0, Interface_name)
        sheet_iperf.write(iteration+1, 1, iperf_result_time)
        sheet_iperf.write(iteration+1, 2, iperf_result_data)
        sheet_iperf.write(iteration+1, 3, iperf_result_bandwidth)
    wb_iperf.save('../../Results/iperf_result.xls')
    print("\nIperf Traffic Generated and result saved in iperf_result.xls file\n")
    # cmd1 = "rm iperf_file*"
    # os.system(cmd1)

def wget_func():
    os.system('mkdir %s/traffic/logs/wget 2>/dev/null'%(pwd_path))
    os.chdir("%s/traffic/logs/wget"%(pwd_path))
    for iteration in range(int(no_of_clients)):
        cmd1 = "ip addr list wifi%s_%s | grep 'inet ' | awk '{print $2}'| cut -d'/' -f1" % (group_number, iteration)
        ip = subprocess.check_output(cmd1, shell=True)
        ip = ip.strip('\n')
        cmd1 = "wget --timeout=10 --bind-address=%s %s -o wget_logfile_%s 2>wget_logfile_%s & " % (ip, wget_link, iteration, iteration)
        os.system(cmd1)
    while 1:
        cmd1 = "ps -ef | grep -w wget | wc -l "
        wget_end_flag = subprocess.check_output(cmd1, shell=True)
        wget_end_flag = int(wget_end_flag.strip('\n'))
        if wget_end_flag == 2:
            break
    sleep(3)
    wget_end_time = str(datetime.now().time())[:-7]
    trash3 = ''
    for iteration in range(int(no_of_clients)):
        trash3 +='\n'+'Wget Output for Interface-%s [ wifi%s_%s ]'.center(50,'*')%(iteration, group_number, iteration)+'\n'
        cmd1 = "head -6 wget_logfile_%s && tail -2 wget_logfile_%s"%(iteration, iteration)
        trash4 = subprocess.check_output(cmd1, shell=True)
        trash3 += trash4
    with open("../../Results/wget_logfile_%s_%s_%s"%(test_shoot_number, group_number, wget_end_time), 'w+') as f:
        f.write(trash3)
    print("\nWget process finished -- logs stored in wget_logfile_%s_%s_%s\n"%(test_shoot_number, group_number, wget_end_time))


file_open = open('conf.yaml')
file_load = yaml.safe_load(file_open)


########### Getting Group Number
while 1:
    group_number = raw_input("\nEnter group number:::")
    group_name = "Group " + group_number
    flag = 0
    while 1:
        if flag:
            group_number = raw_input("\nEnter proper existing group number:::")
            group_name = "Group " + group_number
        cmd1 = "grep '%s' conf.yaml | wc -l" % (group_name)
        group_number_check = subprocess.check_output(cmd1, shell=True)
        group_number_check = group_number_check.strip('\n')
        if group_number_check == '1':
            print '\nGroup number exists'
            break
        elif group_number_check == '0':
            flag = 1
            continue
        else:
            print '\nYou may have duplicate group number enteries, check config file'
            continue

    ########## Reading YAML file
    ssid_details = file_load[group_name]['Connection']
    no_of_clients = file_load[group_name]['No_of_clients']
    ssid = file_load[ssid_details]['SSID']
    key_mgmt = file_load[ssid_details]['key_mgmt']
    if key_mgmt.upper() == 'NONE':
        Encryption = 'off'
        password_print = ''
    else:
        Encryption = 'on'
        password = file_load[ssid_details]['password']
        password_print = '\npassword\t: '+password
    MAC_prefix = file_load[group_name]['MAC_prefix']
    static_ip = file_load[group_name]['Static_ip']
    ip_prefix = file_load[group_name]['ip_prefix']
    netmask = file_load[group_name]['netmask']
    default_gateway = file_load[group_name]['default_gateway']
    dhcp_ip = file_load[group_name]['dhcp_ip']

        ############ Scanning freq and bssid of the given ssid
    wifi_name = subprocess.check_output("iw dev | grep Interface | tail -1 | awk '{print $2}'", shell=True)
    wifi_name = wifi_name.strip('\n')
    cmd1 = "ifconfig | cut -d' ' -f1 | grep -e lo -e wifi"
    up_wifi_list = subprocess.check_output(cmd1, shell=True)
    up_wifi_list = up_wifi_list.split('\n')
    if len(up_wifi_list) == 2:
        scan_wifi = wifi_name
    else:
        scan_wifi = up_wifi_list[1].split(':')[0]
    channel_dict = {'2412': 1, '2417': 2, '2422': 3, '2427': 4, '2432': 5, '2437': 6, '2442': 7, '2447': 8, '2452': 9,
                    '2457': 10, '2462': 11, '5180': 36, '5200': 40, '5220': 44, '5240': 48, '5260': 52, '5280': 56,
                    '5300': 60, '5320': 64, '5500': 100, '5520': 104, '5540': 108, '5560': 112, '5580': 116,
                    '5600': 120, '5620': 124, '5640': 128, '5660': 132, '5680': 136, '5700': 140, '5745': 149,
                    '5765': 153, '5785': 157, '5805': 161, '5825': 165}
    print("\nScanning for Operating Frequency and BSSID of the mentioned SSID. . .\n")
    cmd1 = "iw dev %s scan | grep -wB9 '%s' | grep -e freq -e SSID -e BSS"%(scan_wifi, ssid)
    for iteration in range(3):
        scan_result = sub_process(cmd1)
        if scan_result == 'repeat':
            sleep(3)
            continue
        else:
            break
    no_of_channels  = len(re.findall(r'SSID', scan_result))
    scan_result = scan_result.split('\n')
    if no_of_channels > 1:
        freq_list = []
        print("\nGiven SSID available in %s channel"%(no_of_channels))
        print_str = 'Enter'
        for line in scan_result:
            line_match = re.findall(r'freq', line)
            if line_match:
                freq = line.split()[1]
                print "\n%s. Channel: %s"%(len(freq_list)+1, channel_dict[freq])
                print_str += ' %s to select channel %s,'%(len(freq_list)+1, channel_dict[freq])
                freq_list.append(freq)
        print("\n"+print_str[:-1]+'.')
        channel_select = raw_input("\nEnter number:::")
        while 1:
            if channel_select not in map(str, range(no_of_channels+1))[1:]:
                channel_select = raw_input("\nEnter proper number:::")
            else:
                bssid = scan_result[3*(int(channel_select)-1)].split()[1][:17]
                freq = freq_list[int(channel_select)-1]
                break

    else:
        bssid = scan_result[0].split()[1][:17]
        freq = scan_result[1].split()[1]

    ########### Checking Traffic details
    traffic_details = file_load[group_name]['traffic']
    print ("\nGROUP DETAILS*****\nNo of clients\t: {0}\nssid details\t: {1}\nMAC prefix\t: {2}".format(no_of_clients, ssid_details, MAC_prefix))
    if static_ip:
        print("Static IP\t: {0}\nIP prefix\t: {1}\nNetmask\t\t: {2}\nDef Gateway\t: {3}\n".format("ON", ip_prefix, netmask, default_gateway))
    if dhcp_ip:
        print("DHCP IP\t\t: ON")
    if static_ip == False and dhcp_ip == False:
        print("Static IP\t: OFF\nDHCP IP\t\t: OFF\n\nBoth Static and DHCP IP are OFF\n****Mention any one of the two details for continuing with this group\n")
        continue
    if static_ip == True and dhcp_ip == True:
        print("Static IP\t: ON\nDHCP IP\t\t: ON\n\nBoth Static and DHCP IP cannot be set ON\n****Turn ON only one of the two details for continuing with this group\n")
        continue
    print ("\nSSID DETAILS******\nssid name\t: {0}\nEncryption\t: {1}{2}\nChannel\t\t: {3} [{4} GHz]\nBSSID\t\t: {5}\n".format(ssid, key_mgmt, password_print, channel_dict[freq], float(freq)/1000, bssid))
    print ("\nTRAFFIC DETAILS****")
    if traffic_details == False:
        traffic_flag = '0'
        print("Traffic\t: Nil\n")
    else:
        traffic_flag = '1'
        traffic_details = "Traffic-%s"%(traffic_details)
        iperf = file_load[traffic_details]['iperf']
        ping = file_load[traffic_details]['ping']
        wget = file_load[traffic_details]['wget']
        if (not ping and not iperf and not wget):
            print("\nInvalid Taffic details --- **Mention either Ping or Iperf or wget anyone of them\n")
            continue
        if ping:
            print("Ping Details")
            ping_destination = file_load[traffic_details]['ping_destination']

            ping_no_of_packets = file_load[traffic_details]['ping_no_of_packets']
            ping_no_of_packets_class = Condn(ping_no_of_packets, "\n  No of packets\t\t: %s"%(ping_no_of_packets), "-c %s"%(ping_no_of_packets))
            ping_each_packet_interval = file_load[traffic_details]['ping_each_packet_interval']
            ping_each_packet_interval_class = Condn(ping_each_packet_interval, "\n  Interpacket interval\t: %s (sec)"%(ping_each_packet_interval), "-i %s"%(ping_each_packet_interval))
            ping_run_time = file_load[traffic_details]['ping_run_time(sec)']
            ping_run_time_class = Condn(ping_run_time, "\n  Total run time\t: %s (secs)"%(ping_run_time), "-w %s"%(ping_run_time))
            print ("  Destination\t\t: {0}{1}{2}{3}".format(ping_destination, ping_no_of_packets_class.show, ping_each_packet_interval_class.show, ping_run_time_class.show))
            if ping_run_time == False and ping_no_of_packets == False:
                print("\nInvalid ping details ---\nPing No of packets and run time both are not mentioned\n****Mention atleast one of the two details for continuing this group\n")
                continue
        if iperf:
            print("\nIperf Details")
            iperf_server = file_load[traffic_details]['iperf_server']
            iperf_packets = file_load[traffic_details]['iperf_packets']
            iperf_packets = str(iperf_packets).upper()
            iperf_run_time = file_load[traffic_details]['iperf_run_time(sec)']
            iperf_total_data = file_load[traffic_details]['iperf_total_data']
            iperf_voice_data = file_load[traffic_details]['iperf_voice']
            iperf_video_data = file_load[traffic_details]['iperf_video']

            if iperf_packets not in ['TCP', 'UDP']:
                print("\nInvalid Iperf details --- **Mention either TCP or UDP\n")
                continue
            if iperf_run_time and iperf_total_data:
                print("\nInvalid Iperf details --- **Both Run time and total data cannot be mentioned, Mention any one of them\n")
                continue
            if iperf_voice_data and iperf_video_data:
                print("\nInvalid Iperf details --- **Both voice and video media type cannot be mentioned, Mention any one of them\n")
                continue

            if iperf_packets == 'TCP':
                iperf_packets_cmd = ''
            else:
                iperf_packets_cmd = ' -u '

            if iperf_run_time:
                iperf_time_or_data_print = "\n  Run Time\t: %s (secs)"%(iperf_run_time)
                iperf_time_or_data_cmd = " -t %s "%(iperf_run_time)
            elif iperf_total_data:
                iperf_time_or_data_print = "\n  Total data\t: %s"%(iperf_total_data)
                iperf_time_or_data_cmd = " -n %s "%(iperf_total_data)
            else:
                print("\n[Note: Specify either Iperf run time or Iperf total data otherwise Iperf will run for only 10 secs]")
                iperf_run_time_print = iperf_total_data_print = iperf_run_time_cmd = iperf_total_data_cmd = ''

            if iperf_voice_data:
                iperf_media_print = "\n  Media type\t: Voice"
                iperf_media_cmd = " -S 0xE0 "
            elif iperf_video_data:
                iperf_media_print = "\n Media type\t: Video"
                iperf_media_cmd = " -S 0x80 "
            else:
                iperf_media_cmd = iperf_media_print = ''

            iperf_streams = file_load[traffic_details]['iperf_streams']
            iperf_port_number = file_load[traffic_details]['iperf_port_number']
            iperf_bandwidth = file_load[traffic_details]['iperf_bandwidth']
            iperf_window_size = file_load[traffic_details]['iperf_window_size']
            iperf_buffer_size = file_load[traffic_details]['iperf_buffer_size']

            iperf_streams_class = Condn(iperf_streams, "\n  No of streams\t: %s"%(iperf_streams), " -P %s "%(iperf_streams))
            iperf_port_number_class = Condn(iperf_port_number, "\n  Port number\t: %s"%(iperf_port_number), " -p %s "%(iperf_port_number))
            iperf_bandwidth_class = Condn(iperf_bandwidth, "\n  Bandwidth\t: %s"%(iperf_bandwidth), " -b %s "%(iperf_bandwidth))
            iperf_window_size_class = Condn(iperf_window_size, "\n  Window size\t: %s "%(iperf_window_size), " -w %s "%(iperf_window_size))
            iperf_buffer_size_class = Condn(iperf_buffer_size, "\n  Buffer size\t: %s"%(iperf_buffer_size), " -l %s "%(iperf_buffer_size))
            print ("  Server\t: {0}\n  Packets\t: {1}{2}{3}{4}{5}{6}{7}{8}".format(iperf_server, iperf_packets, iperf_time_or_data_print, iperf_media_print, iperf_streams_class.show, iperf_port_number_class.show, iperf_bandwidth_class.show, iperf_window_size_class.show, iperf_buffer_size_class.show))

        if wget:
            wget_link = file_load[traffic_details]['wget_link']
            print("\nWget Details\n  Wget_link : %s\n"%(wget_link))
    while 1:
        group_flag = raw_input("\nContinue clients simulation for above GROUP Details (y/N): ")
        if group_flag in ['','y', 'Y', 'yes', 'YES', 'n', 'N', 'no', 'NO']:
            break
    if group_flag in ['','y', 'Y', 'yes', 'YES']:
        break


############# Creating WPA_Supplicant File
cmd1 = 'cat /etc/passwd | grep /bin/bash | tail -1 | cut -d: -f1'
username = subprocess.check_output(cmd1, shell=True)
username = username.strip('\n')
pwd_path = subprocess.check_output('pwd', shell=True)
pwd_path = pwd_path.strip('\n')
# os.chdir("%s"%(pwd_path))
# print os.getcwd()
wpa_sup_file = "wpa_supplicant_" + str(group_number) + ".conf"
if os.path.exists("wpa_supplicant_" + str(group_number) + ".conf"):
    os.remove("wpa_supplicant_" + str(group_number) + ".conf")

a = open("wpa_supplicant_" + str(group_number) + ".conf", "w+")
a.write("ap_scan=1\n")
a.write("network={\n")
a.write('  scan_freq=%s\n' % freq)
a.write('  ssid="%s"\n' % ssid)
a.write('  bssid=%s\n' % bssid)
a.write("  scan_ssid=1\n")
if Encryption == 'off':
    a.write("  key_mgmt=NONE\n")
else:
    a.write("  key_mgmt=%s\n " % key_mgmt)
    a.write(' psk="%s"\n' % password)
a.write('}')
a.close()

time_format='%H:%M:%S'
program_start_time = str(datetime.now().time())[:-7]
print 'Program start time = ', program_start_time
cmd1 = "echo '\nScript started at {0} for connecting {1} clients to ssid {2}\n' >> total_log.txt".format(program_start_time, no_of_clients, ssid)
os.system(cmd1)
cmd1 = "tail -f /var/log/syslog | grep -e '] wifi' -e DHCP >> total_log.txt &"
os.system(cmd1)
cmd1 = "service network-manager stop"
os.system(cmd1)
print "Network Manager stopped"
cmd1 = "head -2 /etc/hosts | tail -1 | awk '{print $2}'"
old_hostname = subprocess.check_output(cmd1, shell=True)
old_hostname = old_hostname.strip('\n')
print '\nMultiple Wifi interface creation starts\n'

loop_start_time = str(datetime.now().time())[:-7]

############ Creating Multiple WiFi interface creation
for iteration in range(0, int(no_of_clients)):
    i = str(iteration)
    MAC_suffix = format(iteration, '02X')
    full_MAC = MAC_prefix+MAC_suffix
    new_hostname = "Virtual-%s"%(i)
    cmd1 = "hostname %s" % (new_hostname)
    os.system(cmd1)
    cmd1 = "sed -i 's/%s/%s/g' /etc/hostname" % (old_hostname, new_hostname)
    os.system(cmd1)
    cmd1 = "sed -i 's/%s/%s/g' /etc/hosts" % (old_hostname, new_hostname)
    os.system(cmd1)
    cmd1 = "iw dev %s interface add wifi%s_%s type managed" % (wifi_name, group_number, i)
    os.system(cmd1)
    cmd1 = "ip link set wifi%s_%s address %s" % (group_number, i, full_MAC)
    os.system(cmd1)
    cmd1 = "ifconfig wifi%s_%s up" % (group_number, i)
    os.system(cmd1)
    cmd1 = "wpa_supplicant -B -iwifi%s_%s -Dnl80211 -c ./%s" % (group_number, i, wpa_sup_file)
    os.system(cmd1)
    while 1:
        cmd1 = "iwconfig wifi%s_%s | grep -i %s | wc -l" % (group_number, i, bssid)
        connection_flag = subprocess.check_output(cmd1, shell=True)
        connection_flag = connection_flag.strip('\n')
        sleep(0.2)
        if connection_flag == '1':
            break
    sleep(0.5)

    # ----Configuring IP address
    if dhcp_ip:
        print "\nObtaining IP . . ."
        cmd1 = "dhclient -4 wifi%s_%s" % (group_number, i)
        os.system(cmd1)
    else:
        cmd1 = "ifconfig wifi%s_%s %s%s netmask %s"%(group_number, iteration, ip_prefix, str(iteration+2), netmask)
        os.system(cmd1)
        cmd1 = "route add default gw %s dev wifi%s_%s"%(default_gateway, group_number, i)
        os.system(cmd1)

    cmd1 = "ip addr list wifi%s_%s | grep 'inet ' | awk '{print $2}'| cut -d'/' -f1" % (group_number, i)
    ip = subprocess.check_output(cmd1, shell=True)
    ip = ip.strip('\n')

    pat = re.compile("^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$")
    test = pat.match(ip)
    if test:
        print "\nIP Obtained for wifi%s_%s - %s" % (group_number, i, ip)

        if iteration == 0:
            table_no = str(100 * int(group_number))
        else:
            table_no = str(iteration + 100 * (int(group_number) - 1))

        # print '\nTable no = ',table_no
        cmd1 = "echo '%s rt%s_%s' >> /etc/iproute2/rt_tables"%(table_no, group_number, i)
        os.system(cmd1)
        # print "\nCreating Routing table"
        cmd1 = "route -n | grep UG | head -1 |awk '{print $2}'"
        gateway = subprocess.check_output(cmd1,shell=True)
        gateway = str(gateway).strip('\n')
        # print '\nGateway = %s'%(gateway)
        #gateway = default_gateway

        if gateway == "Gateway":
           print 'IP not obtaining'
           sys.exit()

        cmd1 = "route -n | grep wifi%s_%s | tail -1 |awk '{print $1}'"%(group_number, i)
        ntwk_addr = subprocess.check_output(cmd1,shell=True)
        ntwk_addr = ntwk_addr.strip('\n')
        #print 'Network address = ',ntwk_addr

        cmd1 = "ip route add %s/24 dev wifi%s_%s src %s table rt%s_%s"%(ntwk_addr, group_number, i, ip, group_number, i)
        os.system(cmd1)
        cmd1= "ip route add default via %s dev wifi%s_%s table rt%s_%s"%(gateway, group_number, i, group_number, i)
        os.system(cmd1)
        cmd1 = "ip rule add from %s/32 table rt%s_%s"%(ip, group_number, i)
        os.system(cmd1)
        cmd1 = " ip rule add to %s/32 table rt%s_%s"%(ip, group_number, i)
        os.system(cmd1)
    else:
        print 'IP not obtained properly'
    uptime = str(datetime.now().time())[:-7]
    running_time = str(datetime.strptime(uptime, time_format) - datetime.strptime(program_start_time,time_format))
    delay_time =  str(datetime.strptime(uptime, time_format) - datetime.strptime(loop_start_time,time_format))
    loop_start_time = uptime
    print '\nScript ~~~ Start = %s   uptime = %s   Running = %s   delay = %s \n' % (program_start_time, uptime, running_time, delay_time)
    print '\n----------------------Interface wifi%s_%s completed-----------------\n' % (group_number, iteration)

print 'Wifi interface creation ends\n'
sleep(2)
Interface_creation_end_time = str(datetime.now().time())[:-7]
cmd1 = "pidof tail | xargs kill"
os.system(cmd1)
sleep(2)
# log_thread.join()
cmd1 = "echo '\nScript - Interface creation ends [Time - %s]\n' >> total_log.txt"%(Interface_creation_end_time)
os.system(cmd1)

os.system('mkdir %s/traffic/Results 2>/dev/null')
os.system('mkdir %s/traffic/logs/iperf 2>/dev/null')
os.system('mkdir %s/traffic/logs/Ping 2>/dev/null')
os.chdir("%s/traffic/logs"%(pwd_path))
### Traffic Generation
if traffic_flag=='1':
    print '\n--------------- GENERATING TRAFFIC ------------\n'
    if ping:
        print '\n--------- ping --------\n'
        ping_thread = threading.Thread( target=ping_func, args=() )
        ping_thread.start()

    if iperf:
        print '\n-----IPERF-----\n'
        iperf_thread = threading.Thread( target=iperf_func, args=() )
        iperf_thread.start()

    if wget:
        print("\n-------Wget------\n")
        wget_thread = threading.Thread( target=wget_func, args=() )
        wget_thread.start()

    cmd1 = "chown -R %s ../../traffic" % username
    os.system(cmd1)
