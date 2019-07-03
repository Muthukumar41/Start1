import urllib.request
import urllib.parse
import re
import pafy
import os
import mplayer
import subprocess


queryString = urllib.parse.urlencode({"search_query" : input()})
htmlContent = urllib.request.urlopen("http://www.youtube.com/results?" + queryString)
searchResults = re.findall(r'href=\"\/watch\?v=(.{11})', htmlContent.read().decode())
url = ("http://www.youtube.com/watch?v=" + searchResults[0])

v = pafy.new(url)
print(v.audiostreams)
s = v.getbestaudio()    
