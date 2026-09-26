"""
verify_recovery.py - Independently confirm that CPA really recovered the key.

Instead of comparing the recovered key against the key we told the board to use,
this does a check that trusts NEITHER our "real key" label NOR our CPA code:

  1. Capture (plaintext, ciphertext) pairs from the chip. The ciphertext is what
     the real hardware actually produced - we never assume we know the key.
  2. Run CPA to recover the key from the power traces.
  3. Encrypt the SAME plaintexts with the recovered key using a completely
     separate AES library (PyCryptodome).
  4. If those ciphertexts equal the chip's ciphertexts for every plaintext, the
     recovered key must be the exact key inside the device. That is proof by
     matching the device's real output, not by trusting our own bookkeeping.

Run several keys to be convinced it is not a fluke.
"""

import numpy as np
from tqdm import tqdm
from Crypto.Cipher import AES          # independent AES, unrelated to ChipWhisperer

import chipwhisperer as cw
from capture import connect, flash_firmware
from attack import recover_key

NUM_KEYS       = 3       # how many keys to check this way
TRACES_PER_KEY = 100


def capture_pairs(scope, target, key, n):
    """Record traces and keep the chip's own ciphertext (textout) for each."""
    traces, plaintexts, ciphertexts = [], [], []
    for i in range(n):
        text = bytearray(np.random.randint(0, 256, 16, dtype=np.uint8).tolist())
        trace = cw.capture_trace(scope, target, text, key, always_send_key=(i == 0))
        if trace is None:
            continue
        traces.append(trace.wave)
        plaintexts.append(list(trace.textin))
        ciphertexts.append(bytes(trace.textout))     # what the hardware output
    return np.array(traces), np.array(plaintexts, dtype=np.uint8), ciphertexts


def check_key(recovered, plaintexts, device_ciphertexts):
    """Does the recovered key reproduce the device's real ciphertexts?"""
    cipher = AES.new(bytes(recovered), AES.MODE_ECB)   # separate AES engine
    for pt, ct_device in zip(plaintexts, device_ciphertexts):
        ct_software = cipher.encrypt(bytes(pt))
        if ct_software != ct_device:
            return False
    return True


def main():
    scope, target = connect()
    try:
        flash_firmware(scope)
        all_ok = True
        for k in range(NUM_KEYS):
            key = bytearray(np.random.randint(0, 256, 16, dtype=np.uint8).tolist())
            traces, plaintexts, cts = capture_pairs(scope, target, key, TRACES_PER_KEY)
            recovered = recover_key(traces, plaintexts)

            matches_device = check_key(recovered, plaintexts, cts)
            # We also print the true key just so you can eyeball it, but the proof
            # above does not depend on knowing it.
            print(f"\nkey {k}")
            print(f"  recovered:              {bytes(recovered).hex()}")
            print(f"  (real key, for eyeball) {bytes(key).hex()}")
            print(f"  reproduces device ciphertext for all {len(cts)} plaintexts: "
                  f"{'YES' if matches_device else 'no'}")
            all_ok = all_ok and matches_device
        print("\nOverall:", "all keys independently confirmed" if all_ok
              else "at least one key did NOT confirm")
    finally:
        scope.dis()
        target.dis()


if __name__ == "__main__":
    main()
