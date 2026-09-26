"""
capture.py - Record power traces from a ChipWhisperer-Lite + XMEGA target
while it runs AES-128 encryptions.

Written for chipwhisperer 6.0.0.

Steps:
  1. Connect to the scope (the measuring board) and the target (the XMEGA chip).
  2. Flash the unprotected AES firmware onto the target.
  3. Choose one fixed secret key and many random plaintexts.
  4. For each plaintext, ask the target to encrypt it and record the power used.
  5. Save everything to the data/ folder.
"""

import os
import sys
import importlib

# ---------------------------------------------------------------------------
# Settings you may want to change
# ---------------------------------------------------------------------------
NUM_TRACES  = 200      # how many encryptions to record
NUM_SAMPLES = 5000     # samples per trace (covers the first AES round)
GAIN        = 25       # amplifier gain in dB (higher = bigger signal)

# Where the compiled AES firmware lives (built from the repo copy in ./chipwhisperer)
FIRMWARE_PATH = os.path.join(
    "chipwhisperer", "firmware", "mcu", "simpleserial-aes",
    "simpleserial-aes-CWLITEXMEGA.hex",
)

DATA_DIR    = "data"
RESULTS_DIR = "results"


def print_versions():
    """Check that each needed package is installed and print its version."""
    print("Step 0: checking packages")
    for name in ["chipwhisperer", "numpy", "matplotlib", "tqdm"]:
        try:
            module = importlib.import_module(name)
            print(f"  {name:14s} {module.__version__}")
        except ImportError:
            print(f"  {name} is NOT installed. Run: pip install {name}")
            sys.exit(1)


# Import the packages only after we know they are there.
print_versions()
import numpy as np
import matplotlib
matplotlib.use("Agg")                   # draw plots to files, no window needed
import matplotlib.pyplot as plt
from tqdm import tqdm
import chipwhisperer as cw


def connect():
    """Step 1: find the ChipWhisperer and connect to the scope and target."""
    print("Step 1: connecting to the ChipWhisperer-Lite")
    try:
        scope = cw.scope()
    except Exception:
        print("\n  Could not find the ChipWhisperer.")
        print("  Please check the USB cable is plugged in, then try again.\n")
        sys.exit(1)

    scope.default_setup()               # sensible clock, trigger and serial settings
    scope.gain.db = GAIN                # amplify the tiny power signal
    scope.adc.samples = NUM_SAMPLES     # how many points to record per trace
    target = cw.target(scope)           # serial link to the XMEGA
    print(f"  connected (gain = {GAIN} dB, samples = {NUM_SAMPLES})")
    return scope, target


def flash_firmware(scope):
    """Step 2: load the plain (unprotected) AES program onto the XMEGA."""
    print("Step 2: flashing the AES firmware")
    if not os.path.exists(FIRMWARE_PATH):
        print(f"\n  Firmware not found at {FIRMWARE_PATH}")
        print("  Build it first (see README.md, 'Build the firmware').\n")
        sys.exit(1)                     # main() still disconnects cleanly
    cw.program_target(scope, cw.programmers.XMEGAProgrammer, FIRMWARE_PATH)
    print("  firmware flashed")


def record_traces(scope, target):
    """Steps 3 and 4: fixed key, random plaintexts, record one trace per encryption."""
    print("Step 3: choosing one fixed key and random plaintexts")
    ktp = cw.ktp.Basic()                # ChipWhisperer's key/plaintext generator:
                                        # fixed key by default, random plaintext each time

    print(f"Step 4: recording {NUM_TRACES} traces")
    traces, plaintexts = [], []
    key = None
    for _ in tqdm(range(NUM_TRACES)):
        key, text = ktp.next()          # same key every time, new plaintext
        trace = cw.capture_trace(scope, target, text, key)
        if trace is None:               # the capture timed out; skip this one
            continue
        traces.append(trace.wave)       # the power samples
        plaintexts.append(list(trace.textin))

    print(f"  kept {len(traces)} good traces")
    if len(traces) == 0:
        print("  No traces were captured. Check the target board is seated properly.")
        sys.exit(1)
    return np.array(traces), np.array(plaintexts, dtype=np.uint8), np.array(list(key), dtype=np.uint8)


def save_data(traces, plaintexts, key):
    """Steps 5 and 6: save the numbers, plus a human-readable log."""
    print("Step 5: saving traces.npy, plaintexts.npy, key.npy")
    os.makedirs(DATA_DIR, exist_ok=True)
    np.save(os.path.join(DATA_DIR, "traces.npy"), traces)
    np.save(os.path.join(DATA_DIR, "plaintexts.npy"), plaintexts)
    np.save(os.path.join(DATA_DIR, "key.npy"), key)

    print("Step 6: writing input_log.txt")
    with open(os.path.join(DATA_DIR, "input_log.txt"), "w") as f:
        f.write(f"Real key: {bytes(key).hex()}\n\n")
        f.write("Plaintexts (one per trace):\n")
        for i, pt in enumerate(plaintexts):
            f.write(f"{i:4d}  {bytes(pt).hex()}\n")


def plot_one_trace(traces):
    """Step 7: plot a single trace so we can see the AES round structure."""
    print("Step 7: saving one_trace.png")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    plt.figure(figsize=(10, 4), facecolor="white")
    plt.plot(traces[0], color="tab:blue", linewidth=0.6)
    plt.title("One power trace (AES-128 on XMEGA)")
    plt.xlabel("Sample number")
    plt.ylabel("Power (scaled ADC value)")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "one_trace.png"), dpi=150)
    plt.close()


def main():
    scope, target = connect()
    try:
        flash_firmware(scope)
        traces, plaintexts, key = record_traces(scope, target)
        save_data(traces, plaintexts, key)
        plot_one_trace(traces)
    finally:
        print("Step 8: disconnecting")
        scope.dis()
        target.dis()
    print("Done. Now run: python attack.py")


if __name__ == "__main__":
    main()
