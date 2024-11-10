#!/bin/bash

# Print a message at the start of the script
echo "
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣷⣄⠀⠀⠀⠀⢀⣴⣿⣿⣦⡀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣶⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣷⣄⣠⣶⣿⣿⣿⣿⣿⣿⡆⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⠏⠉⠉⢻⣿⣿⣿⡇⠀⢰⣿⣿⣿⣿⣷⣦⡀⠀⠀⢸⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⣿⠿⠿⠛⠋⠁⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⡟⠛⠻⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⠀⠀⠀⢸⣿⣿⣿⡇⠀⣸⣿⣿⣿⣿⣿⣿⣷⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣤⡆⢾⣿⠗⠺⣿⡷⣰⣤⡀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠻⣿⣿⠟⠋⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⣄⣀⣀⣸⣿⣿⣿⡇⠀⠟⠛⢿⣿⣿⣿⣿⣿⠀⢠⣿⣿⠉⠉⠉⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢙⣻⡄⠀⠀⠀⠀⣠⣟⡋⠁⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠀⠈⠁⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⡇⠀⠀⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⣿⣿⣿⣿⠃⠀⣸⣿⣿⣿⣿⣿⣶⣄⠀⠀⠀⠀
⠀⠀⠀⢀⣾⣿⣿⣿⣶⣤⣤⣾⣿⣿⣿⣷⡀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⣷⣶⣾⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⢰⣿⣿⡿⠃⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀
⠀⠀⠀⣼⡇⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⢸⣧⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⡟⠛⠛⠛⠛⠋⠀⠀⠀⠀⢠⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⢘⣿⣿⣿⡇⠀⠀⠀
⠀⠀⠰⣿⡇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⡇⠀⠀⠀⢸⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⠃⠀⢸⣶⣶⣶⣾⣿⣿⠟⠀⠀⠀⠀
⠀⠀⠀⠈⠁⢙⣛⣛⣛⣛⣛⣛⣛⣛⣋⠈⠁⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠀⠀⠀⠛⠛⠛⠛⠉⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀⠀⠘⠛⠛⠛⠛⠛⠉⠉⠁⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"


# Put wlan0 in monitor mode as mon1 using iw dev
sudo iw dev wlan0 interface add mon1 type monitor
sudo ifconfig mon1 up


cd ~/MDP
# Change directory to client
cd MDP/Client

# Run the Python script with sudo
sudo python main.py -s "MDP-25" -i mon1 -p password1234
ls
# Change directory to ap
cd ../AP
ls
# Run the Python3 script with sudo
sudo python3 ap.py