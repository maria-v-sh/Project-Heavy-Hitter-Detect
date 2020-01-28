# Heavy-Hitter Detection on SmartNIC

Implement HashPipe algorithm on a programmable hardware Netronome SmartNic using P4 language, 
that track the K heaviest flows with high accuracy using limited available memory.

## Getting started
	
1.	In Windows, you must install the Programmer Studio 6.0 program.
2.	Create a project in Programmer Studio 6.0 with files **hh.p4**, **plugin.c**, and **user_config.p4cfg**, from directory **"Packet Processing Code on the Netronome SmartNIC"**.
3.	Run **`Build`**.
4.	Put files **getResult.py** and **Makefile** from directory **"Console code"** to the server.

## Running the tests
	
1.	Run **`Start Debugging`**.
2.	Open 2 consoles.
3.	In the first console, run the command `make tcpdump`
4.	In the second console, run the command `make tcpreplay NUM=... CAPTURE=...`  
    *  The variable **NUM** is the number of packets that we send  
    *  The variable **CAPTURE** is the name of the capture file
5.	In the second console, run the command `make result K=...`  
    *  The variable **K** is number of heavy-hitter flows which we want to check
6.	Run **`End Debugging`**

## Output
	
1.	**Accuracy** of HashPipe Algorithm
2.  **Average** place of HashPipe Algorithm in the sorted list of packets starting from heaviest

## Creators
	
Team: Yevhenii Liubchyk, Maria Shestakova  
Instructors: Itzik Ashkenazi, Prof. Ori Rotenstreich  
Technion - Israel Institute of Technology  