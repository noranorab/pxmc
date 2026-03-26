cat >> ~/.Xresources <<'EOF'
XTerm*selectToClipboard: true
XTerm*VT100.translations: #override \
  Ctrl Shift <Key>C: copy-selection(CLIPBOARD) \n\
  Ctrl Shift <Key>V: insert-selection(CLIPBOARD)
EOF
xrdb -merge ~/.Xresources

#open xterm:# 1) Sanity check
echo "DISPLAY=$DISPLAY"
xauth list "$DISPLAY"

# 2) Export your current X11 cookie to a temp file
xauth extract /tmp/Xauth-$USER "$DISPLAY"

# 3) Merge that cookie into root’s Xauthority
sudo XAUTHORITY=/root/.Xauthority xauth merge /tmp/Xauth-$USER
rm -f /tmp/Xauth-$USER

# 4) (Optional but harmless) also allow root via xhost
xhost +SI:localuser:root


sudo mn -c
sudo pkill -9 -f simple_switch_grpc
make clean
make build
MININET_CLI_NOHISTORY=1 sudo -E env "DISPLAY=$DISPLAY" "XAUTHORITY=/root/.Xauthority" PYTHONPATH=$HOME/tutorials/utils:$HOME/p4runtime/proto:$HOME/googleapis PATH=$HOME/p4local/install/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin LD_LIBRARY_PATH=$HOME/p4local/install/lib HOME=/home/noura $HOME/p4venv/bin/python3 ../../utils/run_exercise.py -t topology.json -j build/pxmc.json -b $HOME/p4local/install/bin/simple_switch_grpc -l /tmp/tutorial-logs -p /tmp/tutorial-pcaps
