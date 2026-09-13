#!/usr/bin/env sh
# ===========================================================================
# docker/agent-entrypoint.sh
# AEGIS Agent container start script
# Launches the heartbeat runner and action consumer daemon in parallel,
# then runs the multi-node simulation scenarios automatically.
# ===========================================================================
set -e

echo "========================================================"
echo " AEGIS EDR Agent Node Starting"
echo " Agent ID         : ${AGENT_ID}"
echo " Command Node     : ${COMMAND_NODE_URL}"
echo " Heartbeat Interval: ${HEARTBEAT_INTERVAL}s"
echo "========================================================"

# Wait for the Command Node to become healthy before starting
echo "[agent] Waiting for Command Node at ${COMMAND_NODE_URL}..."
RETRIES=0
MAX_RETRIES=30
until python -c "import urllib.request; urllib.request.urlopen('${COMMAND_NODE_URL}/api/health', timeout=2)" 2>/dev/null; do
    RETRIES=$((RETRIES+1))
    if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
        echo "[agent] ERROR: Command Node not reachable after ${MAX_RETRIES} retries. Exiting."
        exit 1
    fi
    echo "[agent] ... retrying (${RETRIES}/${MAX_RETRIES})..."
    sleep 2
done

echo "[agent] Command Node is UP. Starting agent daemons..."

# Start heartbeat runner in background
python -m agent.heartbeat_runner &
HEARTBEAT_PID=$!

# Small delay to let heartbeat register before action consumer starts
sleep 1

# Start action consumer daemon (polls for KILL_PROCESS / ISOLATE_HOST commands)
python -m agent.action_consumer \
    --agent-id "${AGENT_ID}" \
    --server "${COMMAND_NODE_URL}" \
    --poll-interval "${POLL_INTERVAL:-2.0}" &
CONSUMER_PID=$!

echo "[agent] Both daemons running. Heartbeat PID=${HEARTBEAT_PID}, Consumer PID=${CONSUMER_PID}"

# Wait for either process to exit
wait -n 2>/dev/null || wait
echo "[agent] Agent daemons exited."
