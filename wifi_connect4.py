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
print(parse['SSID']['ssid1'],parse['SSID']['password1'])
#interface=os.system("cat /proc/net/wireless | awk '{print $1}' | tail -n1 | sed 's/.$//'")
interface=os.system("iw dev | grep Interface | tail -1 | awk '{print $2}'")
#interface=subprocess.check_output("iw dev | grep Interface | tail -1 | awk '{print $2}'",shell=True)
print(interface)
#interface=interface.strip('\n')
print(interface)
os.system("sudo rm /etc/NetworkManager/system-connections/%s*"%parse['SSID']['ssid1'])
print("Going to connect")
os.system("nmcli device wifi connect %s password %s ifname %s"%(parse['SSID']['ssid1'],parse['SSID']['password1'],interface))
#print(ssid,passwd,interface)
sleep(5)
os.system("iwconfig")
sleep(3)
driver = webdriver.ChromeOptions()
driver.add_argument("--start-maximized")
driver = webdriver.Chrome(chrome_options=driver)
driver.get('https://www.youtube.com/')
sleep(15)
order_tab = driver.find_element_by_xpath('//*[@id="search"]')
order_tab.click()
order_tab.send_keys(parse['SSID']['Search'])
search=driver.find_element_by_xpath('//*[@id="search-icon-legacy"]/yt-icon')
search.click()
print("Page opened")
driver.save_screenshot("youtube_search.png")
sleep(5)
#driver.quit()
