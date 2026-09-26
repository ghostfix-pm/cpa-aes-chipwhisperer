# CPA attack on AES-128: ChipWhisperer-Lite (XMEGA)

A small teaching project that records the power a chip uses while it runs AES-128
encryptions, then recovers the secret key from those recordings using
Correlation Power Analysis (CPA).

## What's in here

| Path | What it is |
|---|---|
| `capture.py` | Connects to the board, flashes the AES firmware, records traces, saves them |
| `attack.py` | Loads the traces, runs CPA by hand, recovers the key, saves the results |
| `cpa_multikey.py` | Runs the whole experiment for many random keys and reports the success rate |
| `verify_recovery.py` | Independently confirms a recovered key by matching the chip's real ciphertext |
| `run_cpa_from_notebook.py` | NewAE's tutorial CPA, kept as an independent cross-check |
| `.venv/` | Python virtual environment with the needed packages |
| `chipwhisperer/` | Copy of the ChipWhisperer repo (v6.0.0), used for the firmware source |
| `data/` | Created by `capture.py`: traces, plaintexts, key, readable log |
| `results/` | `one_trace.png` (capture) plus the key report and plots (attack) |

## 1. Set up Python (one time)

The virtual environment already exists. To rebuild it from scratch:

```bash
python3 -m venv .venv
.venv/bin/pip install chipwhisperer numpy matplotlib tqdm
```

## 2. Build the firmware (one time)

The XMEGA needs the `simpleserial-aes` program, compiled with `avr-gcc`.

```bash
brew tap osx-cross/avr
brew trust --formula osx-cross/avr/avr-gcc@9 osx-cross/avr/avr-binutils osx-cross/avr/avr-libc
brew install osx-cross/avr/avr-gcc@9
export PATH=/opt/homebrew/opt/avr-gcc@9/bin:$PATH
cd chipwhisperer/firmware/mcu/simpleserial-aes
make PLATFORM=CWLITEXMEGA CRYPTO_TARGET=TINYAES128C
cd -
```

This creates `simpleserial-aes-CWLITEXMEGA.hex`, which is the file `capture.py` flashes.

## 3. Capture traces

Plug in the ChipWhisperer-Lite over USB, then run:

```bash
.venv/bin/python capture.py
```

Each step prints a line as it runs. When it finishes:

- `data/traces.npy`: one row of power samples per encryption
- `data/plaintexts.npy`: the 16-byte plaintext used for each row
- `data/key.npy`: the fixed key the target used
- `data/input_log.txt`: the key in hex, then every plaintext, one per line
- `results/one_trace.png`: a single trace. Open it and check that you can see
  repeating patterns (the AES rounds) before trusting the data.

## 4. Run the attack

```bash
.venv/bin/python attack.py
```

This reads only the real traces in `data/` and, for each of the 16 key bytes,
tries all 256 guesses and keeps the one whose predicted power best correlates
with the measurements. It writes:

- `results/recovered_key.txt`: recovered key, real key, MATCH yes/no, and a
  per-byte table (recovered, real, correct?).
- `results/correlation_plot.png`: byte 0, the correct guess (orange) spiking
  above all 255 wrong guesses (grey).
- `results/traces_needed.png`: byte 0, the correct guess pulling away from the
  wrong ones as more traces are used.

`run_cpa_from_notebook.py` performs the same recovery a second way (NewAE's
tutorial code, pointed at your `data/`) if you want to confirm the result
independently.

## 5. Run the experiment for many keys

```bash
.venv/bin/python cpa_multikey.py
```

This picks `NUM_KEYS` random keys (default 20), captures `TRACES_PER_KEY`
traces for each, recovers each key with CPA, and writes
`results/multikey_summary.txt`. Each key gets two independent checks:

- **Fully recovered?** all 16 recovered bytes equal the key we told the board to use.
- **Confirmed vs device output?** the recovered key, run through a *separate* AES
  library (PyCryptodome), reproduces the ciphertext the chip actually output for
  every plaintext. This trusts neither our stored key nor our CPA code, so it is
  the real proof that the key was recovered.

`verify_recovery.py` does only that second, independent check, for a few keys,
if you want to see it on its own.

## Note: USB "could not find" errors

If a script says it cannot find the ChipWhisperer even though the cable is
plugged in, a previous run may still be holding the USB device. Find and stop it:

```bash
ps aux | grep [p]ython      # look for a script still running
kill <PID>
```

## Settings

At the top of `capture.py`:

```python
NUM_TRACES  = 200    # how many encryptions to record
NUM_SAMPLES = 5000   # samples per trace
GAIN        = 25     # amplifier gain in dB
```

## Troubleshooting

- **"Could not find the ChipWhisperer"**: check the USB cable, then unplug it and plug it back in.
- **"Firmware not found"**: do step 2 first.
- **"No traces were captured"**: make sure the XMEGA target is seated on the board.
