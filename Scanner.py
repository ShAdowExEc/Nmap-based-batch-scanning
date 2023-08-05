import nmap
from urllib.parse import urlparse
import sys
import argparse

print("***********by ShAdowExEc*************")
print("***********请首先确保已经安装了NMAP并加入环境变量*************")
print('***********基于nmap对多个目标ip:port批量扫描  [eg: python scanner.py -add  "-sC -sV -T4 --script ssl-enum-ciphers"]***********')
print('\n')  
domains='domain.txt'
resultfile='scanresult.txt'

parser = argparse.ArgumentParser(description='基于nmap对多个目标ip:port批量扫描  [eg: python scanner.py -add  "-sC -sV -T4"]')
    
parser.add_argument('-m', dest='mode', type=str, help='添加nmap的参数，如-sC -sV -T4 --script ssl-enum-ciphers', default=True)
  
args = parser.parse_args(sys.argv[1:])
 
_add=args.mode 

def write(file,text):
    with open(file, "a", encoding='utf-8',newline='') as f:
      f.write(text)


def check(ip,port,ad):
    n=nmap.PortScanner()
    result=n.scan(hosts='{}'.format(ip), ports='{}'.format(port), arguments='{}'.format(ad))
    
    return result['scan'][ip]['tcp'][port]

def resultwrite(file,result,ip,port):
     with open(file, "a", encoding='utf-8',newline='') as f:
       f.write(ip+':'+str(port))
       kkeys=list(result.keys())[:-1]
       for kkey in kkeys:
         
         f.write(str(kkey)+':'+str(result[kkey]))
         f.write('\n')
       
       for key,values in result['script'].items(): 
         

         f.write(str(key)+':'+str(values))
         f.write('\n')
       f.write('\n----------------------------------------------------------------------------\n')

with open(domains, "r", encoding='utf-8') as f:

    urls = f.readlines()
    for urli in urls:
        url=urli.strip()
        try:
            _url = urlparse('http://'+url)
            hostname = _url.hostname
            port = _url.port
            scan_result=check(hostname,port,_add)
            resultwrite(resultfile,scan_result,hostname,port)
            print(url+' '+' ---done')
        except Exception as e:
            print(url+' '+' ---connection error')
            write(resultfile,url+' '+' ---connection error'+"\r\n")
            write(resultfile,'\n----------------------------------------------------------------------------\n')

