# Securitylab Project - Root Privileges Reverse Shell

## Team Member
Sittichok Thanomkulrat and Xianze Zhan

## Tested Environment
Ubuntu 16.04(64 bit) with Kernel 4.4.0

## What Does it do?
We implemented a rootkit module. It can hide itself from the module list and grant the root access for standard user after it has been installed. The non-root user can then run the reverse shell script to open a root reverse shell and connect back to the attacker. 

## File You May Care
- install_rootkit.sh
- reverse_shell.sh
- rootkit.c
- rootkit.h

## How to Load & Run? <br />
On target bot side: 
  ```bash
  make
  sudo ./install_rootkit.sh
  ```
  
On Attacker side: <br />
 ```bash
 nc -l -p <listen_port> -vvv 
 ```
  
Standard user on target side:<br />
 ```bash
  ./reverse_shell.sh 
 ```
You may modify the attacker server ip address & listen port in the reverse_shell script <br />

## How to Unload?<br />
  ```bash
  echo "unhide" > /proc/CS460/status
  sudo rmmod rootkit
  ```

## Warning!!!<br/>
This project is designed for academic research and study usage only.<br /> 
Don't be evil! Do Not use it against any unauthorised users in the real world! 