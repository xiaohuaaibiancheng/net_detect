# 介绍
CICFlowMeter是一个开源工具，它从pcap文件生成Biflow，并从这些流中提取特征。

CICFlowMeter是一个网络流量生成器，可从这里获得。它可用于生成双向流，其中第一个数据包确定前进（源到目的地）和后向（目的地到源）方向，因此可以在向前和向后方向上分别计算与统计时间相关的特征。其他功能包括从现有功能列表中选择功能、添加新功能以及控制流超时的持续时间。

注意：TCP 流通常在连接断开时终止（通过 FIN 数据包），而 UDP 流则因流超时而终止。流超时值可以由单个方案任意分配，例如，TCP 和 UDP 的 600 秒。

----------------------------------------

# Installation and executing:

Extract CICFlowMeterV3.zip

___Note: The only prerequisite is that "libpcap" library or WinPcap on windows systems, be pre-installed___


For Linux

> $ sudo apt-get install libpcap-dev


For windows
> download [winpcap](<https://www.winpcap.org/install/default.htm>)

## executing
Go to the extracted directory,enter the 'bin' folder

### linux
Open a terminal and run this command
```
//For GUI:
sudo ./CICFlowMeter

//For Command line:
./cfm "inputFolder" "outputFolder"
```
### windows
Lanunch the Comand Prompt and run this command
```
//for GUI:
CICFlowMeter.bat

//for Commond line:
cfm.bat "inputFolder" "outputFolder"
```

## Get started
for offline
```
1.Select the folder that include your PCAP files
2.Select the folder that you would like to save you CSV files
3.Click OK button
```

for realtime
```
1 CLick Load button to find the list of network interfaces
2 Select the interface you would like to monitor
3 Click start button and wait for a while
4 Click stop button to stop the process and save the csv in same applcation folder/data/daily
```

--------------------------------------------------------------

