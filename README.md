# Nmap-based-batch-scanning
## 脚本仅供交流学习或进行被授权的扫描，禁止用于未授权扫描他人资产！随意使用有触犯法律的风险，请遵守法律法规，违反法律责任自负！
### 基于nmap，用于批量扫描ip:port形式的目标 

#### 注意：  
    脚本基于nmap，务必安装nmap且加入环境变量！  
    需要python3！  
    需要python-nmap包！（pip install python-nmap）  
#### 使用方式：      
    将ip:port按行写入文件domain.txt，使用脚本批量扫描，如： [ python Scanner.py -m "-sC -sV --script ssl-enum-ciphers" ]，根据需要更换add的脚本名(务必使用双引号)。  
#### 可能出现的问题：    
    1.脚本扫描期间卡住-----众所周知nmap经常会卡住，脚本也是完美继承了本特点，卡住的话可以ctrl+c中断脚本，从卡住的地方重新跑（将domain.txt里面卡住之前的地方删掉）  
    2.挂代理导致脚本无法运行-----挂了系统代理nmap就g，可以通过添加命令进行解决，eg：python Scanner.py -m "-sC -sV --script ssl-enum-ciphers -PN -sT localhost"    
    3.scanresult.txt查看结果
#### domain.txt文件示例：  
![image](https://github.com/Shadowexec/Nmap-based-batch-vulnerability-scanning/assets/74530423/c5c9f46d-d152-4814-b3b3-61da4c676ac7)
