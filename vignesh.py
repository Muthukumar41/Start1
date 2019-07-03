from selenium import webdriver
from time import sleep
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.select import Select

driver = webdriver.ChromeOptions()
driver.add_argument("--start-maximized")
driver = webdriver.Chrome(chrome_options=driver)
driver.get('https://www.facebook.com/')
print("Page opened")
driver.quit()
