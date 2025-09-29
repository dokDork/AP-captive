# AP-captive
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)  
AP-captive creates a passwordless access point that can be connected to. Connecting users are still prompted to enter a password, which is saved by the access point.
<img src="https://github.com/dokDork/AP-captive/raw/main/images/ap-captive.png" width="250" height="250">  

## Description
**AP-captive** AP-captive is activated on a PC (e.g., a Kali Linux) that uses three antennas to operate:
- antenna0 (e.g., wlan0): Used to connect Kali Linux to the Internet;
- antenna1 (e.g., wlan1): Used to activate an Access Point with a specific ESSID;
- antenna2 (e.g., wlan2): Used to perform deauthentication attacks on antennas with the same ESSID.

  
## Example Usage
 ```
sudo ./AP-captive.sh TryHackMe wlan0 wlan1 wlan2 --nm-stop
 ``` 
<img src="https://github.com/dokDork/AP-captive/raw/main/images/command.jpg">

select one of the penetration test PHASES you are interested in:
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/02.png">

Once selected the PHASE, scripts will be generated using tmux as terminal.
At this point you can select a specific SUB-PHASE using tmux commands:  
**(CTRL + b) w**  
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/03.png">

once the SUB-PHASE has been selected you will be able to view the commands that have been pre-compiled to analyse the SUB-PHASE. At this point it is possible to selecet and execute a specific command just pressing ENTER:
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/04.png">

When you need to change penetration test PHASE and return to main manu, you need to close the tmux session. To implement this action you need to use the tmux shortcut:  
**(CTRL + b) :kill-session**  
or, if you configure tmux as reported in the Installation section, you can use the shortcut:
**(CTRL + b) (CTRL + n)**  

<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/05.png">

  
## Command-line parameters
```
./siteSniper.sh <interface> <target url>
```

| Parameter | Description                          | Example       |
|-----------|--------------------------------------|---------------|
| `interface`      | network interface through which the target is reached | `eth0`, `wlan0`, `tun0`, ... |
| `target url`      | Target URL you need to test          | `http://www.example.com`          |

  
## How to install it on Kali Linux (or Debian distribution)
It's very simple  
```
cd /opt
sudo git clone https://github.com/dokDork/SiteSniper.git
cd SiteSniper 
chmod 755 siteSniper.sh 
./siteSniper.sh 
```
Optional: You can insert a shortcut to move faster through the tool.
```
echo "bind-key C-n run-shell \"tmux kill-session -t #{session_name}\"" >> ~/.tmux.conf
```

