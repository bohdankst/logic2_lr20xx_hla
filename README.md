
# Semtech LR20xx HLA

A [Saleae Logic 2](https://www.saleae.com/) High-Level Analyzer extension for decoding SPI communication with the **Semtech LR20xx** series of multi-protocol radio transceivers (e.g. LR2021).

## Features

- **Command decoding** — identifies every SPI transaction by its two-byte opcode and displays the human-readable command name (150+ commands across LoRa, FSK, FLRC, BLE, OOK, OQPSK, Wi-SUN, WM-Bus, Z-Wave, RTToF, FIFO, and System groups).
- **Status decoding** — extracts the command-status field from the MISO status byte and displays `OK`, `DATA`, `FAIL`, or `PERR`. Each status maps to a distinct color in the Logic 2 UI.
- **Mode info** — decodes the chip operating mode (SLEEP, STDBY_RC, STDBY_XOSC, FS, RX, TX) returned in every MISO status byte.
- **Interrupt flag** — highlights transactions where the interrupt line is asserted and, for write/set/clear commands, shows the raw interrupt bytes.
- **Reset source** — reports the reset source (Analog, NRESET) when a reset event is present in the status byte.
- **Value parsing** — parses payload values for supported commands into human-readable form (e.g. `RADIO_COMMON_SET_RF_FREQ_OC` → frequency in Hz).
- **SPI error detection** — flags SPI framing errors as a separate frame type.

All features except command decoding can be individually toggled via the analyzer settings in Logic 2.

## Setup

1. Attach the **SPI** analyzer to your capture in Logic 2.
2. Add the **lr20xx** HLA on top of the SPI analyzer.
3. Tune the settings (Status Info, Mode Info, Interrupt Status, Reset Info, Value Parse) to show only what you need.

## Settings

| Setting | Description |
|---|---|
| Enable Status Info | Show command execution status (OK / DATA / FAIL / PERR) |
| Enable Mode Info | Show chip operating mode |
| Enable Interrupt Status | Highlight transactions with active interrupt; show raw interrupt bytes for write-type commands |
| Enable Reset Info | Show reset source when a reset is detected |
| Enable Value Parse (if supported) | Parse payload into a human-readable value (e.g. RF frequency in Hz) |
