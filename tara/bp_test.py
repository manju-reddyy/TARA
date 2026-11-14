"""One-shot: connect to the board like the bridge does, send one 'approve' command, print the result."""
import time
from board_push import BoardPush

def log(m): print(time.strftime("%H:%M:%S"), m, flush=True)

bp = BoardPush(log=log)
for _ in range(60):
    if bp.remote_connected():
        break
    time.sleep(1)
print("BOARD_CONNECTED:", bp.remote_connected(), flush=True)
if bp.remote_connected():
    r = bp.request_fingerprint("TEST approval - place your finger", wait_s=45)
    print("RESULT (matched, finger_id):", r, flush=True)
else:
    print("board never connected to this test server", flush=True)
time.sleep(1)
