#!/usr/bin/env bash
set -euo pipefail

# ---- Config you might tweak ----
TOPODIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/tmp/tutorial-logs"
PCAP_DIR="/tmp/tutorial-pcaps"
P4JSON="$TOPODIR/build/pxmc.json"
TOPO="$TOPODIR/topology.json"
BMV2_BIN="$HOME/p4local/install/bin/simple_switch_grpc"
PYTHON="$HOME/p4venv/bin/python3"
UTILS_DIR="$HOME/tutorials/utils"
P4RT_PROTO="$HOME/p4runtime/proto"
GOOGLEAPIS="$HOME/googleapis"
EXE="$TOPODIR/../../utils/run_exercise.py"

# ---- Allow root to open X windows (xterm) on your display (optional) ----
# If you're on a local desktop X session, this helps avoid the
# "X11 connection rejected because of wrong authentication" error.
xhost +SI:localuser:root >/dev/null 2>&1 || true

echo "[*] Cleaning previous Mininet/BMv2 state..."
sudo pkill -9 -f simple_switch_grpc || true
sudo mn -c || true

echo "[*] Ensuring output directories exist..."
mkdir -p "$LOG_DIR" "$PCAP_DIR"

echo "[*] Launching exercise..."
#!/usr/bin/env bash
set -euo pipefail

# ---- Config you might tweak ----
TOPODIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/tmp/tutorial-logs"
PCAP_DIR="/tmp/tutorial-pcaps"
P4JSON="$TOPODIR/build/pxmc.json"
TOPO="$TOPODIR/topology.json"
BMV2_BIN="$HOME/p4local/install/bin/simple_switch_grpc"
PYTHON="$HOME/p4venv/bin/python3"
UTILS_DIR="$HOME/tutorials/utils"
P4RT_PROTO="$HOME/p4runtime/proto"
GOOGLEAPIS="$HOME/googleapis"
EXE="$TOPODIR/../../utils/run_exercise.py"

# ---- Allow root to open X windows (xterm) on your display (optional) ----
# If you're on a local desktop X session, this helps avoid the
# "X11 connection rejected because of wrong authentication" error.
xhost +SI:localuser:root >/dev/null 2>&1 || true

echo "[*] Cleaning previous Mininet/BMv2 state..."
sudo pkill -9 -f simple_switch_grpc || true
sudo mn -c || true

echo "[*] Ensuring output directories exist..."
mkdir -p "$LOG_DIR" "$PCAP_DIR"

echo "[*] Launching exercise..."
sudo -E env \
  "XAUTHORITY=$HOME/.Xauthority" \
  PYTHONPATH="$UTILS_DIR:$P4RT_PROTO:$GOOGLEAPIS" \
  PATH="$HOME/p4local/install/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin" \
  LD_LIBRARY_PATH="$HOME/p4local/install/lib" \
  HOME="$HOME" \
  "$PYTHON" "$EXE" \
    -t "$TOPO" \
    -j "$P4JSON" \
    -b "$BMV2_BIN" \
    -l "$LOG_DIR" \
    -p "$PCAP_DIR"
