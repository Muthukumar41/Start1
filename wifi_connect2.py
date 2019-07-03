import os, sys
from selenium import webdriver
from time import sleep
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.select import Select
import subprocess
 
print("Enter your Option")
print(" 1. Active Wifi (up)\n 2. Down Wifi (down)\n 3. Exit")
inp_up_down = input("Enter choice number: ")
if inp_up_down == '1':
#    interface,check=commands.getstatusoutput("cat /proc/net/wireless | awk '{print $1}' | tail -n1 | sed 's/.$//'")
    interface=os.system("cat /proc/net/wireless | awk '{print $1}' | tail -n1 | sed 's/.$//'")
#    interface = interface[] 
    print(interface)
#    os.system("ifconfig %s up"%interface)
    print ("in")
    print(" Are you want connect to wifi?")
    print(" 1. Yes, Connect\n 2. No, Exit")
    inp_connect = input("Enter your choice: ")
    if inp_connect == '1':
#        os.system("iwlist wlp6s0 scan | grep ESSID")
        ssid = input("Enter name of wifi: ")
        passwd = input("Enter the password:")
#        os.system("cd /etc/NetworkManager/system-connections")
        os.system("sudo rm /etc/NetworkManager/system-connections/%s*"%ssid)
#        os.system("iwconfig %s essid "%(interface,ssid))
        print("Going to connect")
        os.system("nmcli device wifi connect %s password %s ifname %s"%(ssid,passwd,interface))
        print(ssid,passwd,interface)
        sleep(5)
        os.system("nmcli connection")
        os.system("iwconfig")
        sleep(3)
        driver = webdriver.ChromeOptions()
        driver.add_argument("--start-maximized")
        driver = webdriver.Chrome(chrome_options=driver)
        driver.get('https://www.facebook.com/')
        print("Page opened")
        sleep(5)
        driver.quit()

    elif inp_connect == '2':
        print("Thankyou..")
        sys.exit()
elif inp_up_down == '2':
    os.system("ifconfig wlan0 down")
elif inp_up_down == '3':
    sys.exit()
else:
    print("Sorry,Wrong Input!!")


