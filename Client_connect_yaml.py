import os, sys
from selenium import webdriver
from time import sleep
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.select import Select
import subprocess
import yaml

document=open('wifi_config.yaml','r')
parse=yaml.safe_load(document)
#parse = yaml.dump(parse)
print(parse)
print(parse['SSID']['ssid'])
#interface=os.system("cat /proc/net/wireless | awk '{print $1}' | tail -n1 | sed 's/.$//'")
interface=os.system("iw dev | grep Interface | tail -1 | awk '{print $2}'")
print(interface)
os.system("sudo rm /etc/NetworkManager/system-connections/%s*"%parse['SSID']['ssid'])
print("Going to connect")
os.system("nmcli device wifi connect %s password %s ifname %s"%(parse['SSID']['ssid'],parse['SSID']['password'],interface))
#print(ssid,passwd,interface)
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
