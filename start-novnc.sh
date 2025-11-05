#!/usr/bin/env bash
set -e

# X display / VNC ports
DISPLAY_NUM=1
XVFB_DISPLAY=":${DISPLAY_NUM}"
VNC_PORT=5901
NOVNC_PORT=6080

echo "[pyzenmap] Starting Xvfb on ${XVFB_DISPLAY}..."
Xvfb ${XVFB_DISPLAY} -screen 0 1280x800x24 &>/tmp/xvfb.log &
sleep 0.8

export DISPLAY=${XVFB_DISPLAY}

echo "[pyzenmap] Starting minimal window manager (fluxbox)..."
fluxbox &>/tmp/fluxbox.log &
sleep 0.6

echo "[pyzenmap] Starting x11vnc on display ${XVFB_DISPLAY} (VNC port ${VNC_PORT})..."
# -nopw for no password inside Codespace (do not use publicly)
x11vnc -display ${XVFB_DISPLAY} -nopw -rfbport ${VNC_PORT} -forever -shared &>/tmp/x11vnc.log &
sleep 0.8

# Start noVNC proxy (websocket -> vnc)
if [ -d /opt/noVNC ]; then
  echo "[pyzenmap] Starting noVNC proxy on port ${NOVNC_PORT}..."
  # use bundled novnc proxy script (novnc provides utils/novnc_proxy.sh or utils/novnc_proxy)
  /opt/noVNC/utils/novnc_proxy --vnc localhost:${VNC_PORT} --listen ${NOVNC_PORT} &>/tmp/novnc.log &
  sleep 0.8
else
  echo "[pyzenmap] noVNC not found in /opt/noVNC"
fi

echo "[pyzenmap] Starting pyzenmap GUI on DISPLAY=${DISPLAY} ..."
# run the GUI; use "&" if you want it in background
python3 pyzenmap.py &

echo "[pyzenmap] Done. Open the forwarded port 6080 in Codespaces 'Ports' view or click the 'Open in Browser' link."
tail -f /dev/null
