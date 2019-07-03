import os, sys
from selenium import webdriver
from time import sleep
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.select import Select
import subprocess
 
interface=os.system("cat /proc/net/wireless | awk '{print $1}' | tail -n1 | sed 's/.$//'")
print(interface)
#ssid = input("Enter name of wifi: ")
#passwd = input("Enter the password:")
os.system("sudo rm /etc/NetworkManager/system-connections/%s*"%ssid)
print("Going to connect")
os.system("nmcli device wifi connect %s password %s ifname %s"%(ssid,passwd,interface))
print(ssid,passwd,interface)
sleep(5)
os.system("iwconfig")
sleep(3)
driver = webdriver.ChromeOptions()
driver.add_argument("--start-maximized")
driver = webdriver.Chrome(chrome_options=driver)
driver.get('https://www.facebook.com/')
print("Page opened")
sleep(5)
driver.quit()
