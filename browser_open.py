#import webbrowser
#webbrowser.open_new('https://gmail.com')
import webbrowser
import time
 
url = 'http://www.mattcole.us/'
url2 = 'http://facebook.com/'
url3 = 'https://gab.ai/home'
url4 = 'https://duckduckgo.com/'
 
chrome_path = '/usr/bin/chromedriver'
 
webbrowser.get(chrome_path).open(url)
time.sleep(2)
webbrowser.get(chrome_path).open_new_tab(url2)
time.sleep(2)
webbrowser.get(chrome_path).open_new_tab(url3)
time.sleep(2)
webbrowser.get(chrome_path).open_new_tab(url4)
