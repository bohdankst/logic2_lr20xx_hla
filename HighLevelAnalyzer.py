# High Level Analyzer for LR20xx SPI protocol
# For more information and documentation, please go to
# https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# --------------------------------------------------------------------------- #
# LR20xx command table (MOSI first two bytes → name)
# Keys are (byte0, byte1) tuples.
# Extend this dict as you add supported commands.
# --------------------------------------------------------------------------- #
COMMAND_TABLE = {
        (0x02, 0x60): 'RADIO_BLUETOOTH_LE_SET_MODULATION_PARAMS_OC',
        (0x02, 0x61): 'RADIO_BLUETOOTH_LE_SET_PKT_PARAMS_OC',
        (0x02, 0x62): 'RADIO_BLUETOOTH_LE_SET_TX_OC',
        (0x02, 0x64): 'RADIO_BLUETOOTH_LE_GET_RX_STATS_OC',
        (0x02, 0x65): 'RADIO_BLUETOOTH_LE_GET_PKT_STATUS_OC',
        (0x02, 0x66): 'RADIO_BLUETOOTH_LE_SET_PDU_LENGTH_OC',

        (0x02, 0x50): 'RADIO_BPSK_SET_MODULATION_PARAMS_OC',
        (0x02, 0x51): 'RADIO_BPSK_SET_PACKET_PARAMS_OC',

        (0x01, 0x23): 'RADIO_COMMON_CALIBRATE_FRONT_END_OC',
        (0x02, 0x00): 'RADIO_COMMON_SET_RF_FREQ_OC',
        (0x02, 0x01): 'RADIO_COMMON_SET_RX_PATH_OC',
        (0x02, 0x02): 'RADIO_COMMON_SET_PA_CFG_OC',
        (0x02, 0x03): 'RADIO_COMMON_SET_TX_PARAMS_OC',
        (0x02, 0x05): 'RADIO_COMMON_SET_RSSI_CALIBRATION_OC',
        (0x02, 0x06): 'RADIO_COMMON_SET_RX_TX_FALLBACK_MODE_OC',
        (0x02, 0x07): 'RADIO_COMMON_SET_PKT_TYPE_OC',
        (0x02, 0x08): 'RADIO_COMMON_GET_PKT_TYPE_OC',
        (0x02, 0x09): 'RADIO_COMMON_SET_RX_TIMEOUT_STOP_EVENT_OC',
        (0x02, 0x0A): 'RADIO_COMMON_RESET_RX_STATS_OC',
        (0x02, 0x0B): 'RADIO_COMMON_GET_RSSI_INST_OC',
        (0x02, 0x0C): 'RADIO_COMMON_SET_RX_OC',
        (0x02, 0x0D): 'RADIO_COMMON_SET_TX_OC',
        (0x02, 0x0E): 'RADIO_COMMON_SET_TX_TEST_MODE_OC',
        (0x02, 0x0F): 'RADIO_COMMON_SEL_PA_OC',
        (0x02, 0x10): 'RADIO_COMMON_SET_RX_DUTY_CYCLE_OC',
        (0x02, 0x11): 'RADIO_COMMON_CONFIGURE_AUTO_TX_RX',
        (0x02, 0x12): 'RADIO_COMMON_GET_RX_PACKET_LENGTH_OC',
        (0x02, 0x15): 'RADIO_COMMON_SET_DEFAULT_RX_TX_TIMEOUT_OC',
        (0x02, 0x16): 'RADIO_COMMON_SET_TIMESTAMP_SOURCE_OC',
        (0x02, 0x17): 'RADIO_COMMON_GET_TIMESTAMP_VALUE_OC',
        (0x02, 0x18): 'RADIO_COMMON_SET_CCA_OC',
        (0x02, 0x19): 'RADIO_COMMON_GET_CCA_RESULT_OC',
        (0x02, 0x1A): 'RADIO_COMMON_SET_AGC_GAIN_OC',
        (0x02, 0x1B): 'RADIO_COMMON_SET_CAD_PARAMETERS_OC',
        (0x02, 0x1C): 'RADIO_COMMON_SET_CAD_OC',

        (0x00, 0x01): 'RADIO_FIFO_READ_RX_OC',
        (0x00, 0x02): 'RADIO_FIFO_WRITE_TX_OC',
        (0x01, 0x14): 'RADIO_FIFO_CLEAR_FIFO_IRQ_FLAGS_OC',
        (0x01, 0x1A): 'RADIO_FIFO_CFG_IRQ_OC',
        (0x01, 0x1B): 'RADIO_FIFO_GET_IRQ_OC',
        (0x01, 0x1C): 'RADIO_FIFO_GET_RX_LEVEL_OC',
        (0x01, 0x1D): 'RADIO_FIFO_GET_TX_LEVEL_OC',
        (0x01, 0x1E): 'RADIO_FIFO_CLEAR_RX_OC',
        (0x01, 0x2E): 'RADIO_FIFO_GET_AND_CLEAR_IRQ_FLAGS_OC',
        (0x01, 0x1F): 'RADIO_FIFO_CLEAR_TX_OC',

        (0x02, 0x48): 'RADIO_FLRC_SET_MODULATION_PARAMS_OC',
        (0x02, 0x49): 'RADIO_FLRC_SET_PKT_PARAMS_OC',
        (0x02, 0x4A): 'RADIO_FLRC_GET_RX_STATS_OC',
        (0x02, 0x4B): 'RADIO_FLRC_GET_PKT_STATUS_OC',
        (0x02, 0x4C): 'RADIO_FLRC_SET_SYNCWORD_OC',

        (0x02, 0x40): 'RADIO_FSK_SET_MODULATION_PARAMS_OC',
        (0x02, 0x41): 'RADIO_FSK_SET_PACKET_PARAMS_OC',
        (0x02, 0x42): 'RADIO_FSK_SET_WHITENING_PARAMS_OC',
        (0x02, 0x43): 'RADIO_FSK_SET_CRC_PARAMS_OC',
        (0x02, 0x44): 'RADIO_FSK_SET_SYNCWORD_OC',
        (0x02, 0x45): 'RADIO_FSK_SET_ADDRESSES_OC',
        (0x02, 0x46): 'RADIO_FSK_GET_RX_STATISTICS_OC',
        (0x02, 0x47): 'RADIO_FSK_GET_PACKET_STATUS_OC',

        (0x02, 0x1E): 'RADIO_LORA_SET_SIDE_DETECTOR_CONFIGURE_CAD_OC',
        (0x02, 0x20): 'RADIO_LORA_SET_MODULATION_PARAMS_OC',
        (0x02, 0x21): 'RADIO_LORA_SET_PACKET_PARAMS_OC',
        (0x02, 0x22): 'RADIO_LORA_SET_LORA_SEARCH_SYMBOLS_OC',
        (0x02, 0x23): 'RADIO_LORA_SET_SYNCWORD_OC',
        (0x02, 0x24): 'RADIO_LORA_CONFIGURE_SIDE_DETECTORS_OC',
        (0x02, 0x25): 'RADIO_LORA_SET_SIDE_DETECTOR_SYNCWORD_OC',
        (0x02, 0x27): 'RADIO_LORA_CONFIGURE_CAD_PARAMS_OC',
        (0x02, 0x28): 'RADIO_LORA_SET_CAD_OC',
        (0x02, 0x29): 'RADIO_LORA_GET_RX_STATISTICS_OC',
        (0x02, 0x2A): 'RADIO_LORA_GET_PACKET_STATUS_OC',
        (0x02, 0x2B): 'RADIO_LORA_SET_ADDRESS_OC',
        (0x02, 0x2C): 'RADIO_LORA_SET_FREQ_HOP_OC',

        (0x02, 0x56): 'RADIO_LR_FHSS_BUILD_FRAME_OC',
        (0x02, 0x57): 'RADIO_LR_FHSS_SET_SYNCWORD_OC',

        (0x02, 0x81): 'RADIO_OOK_SET_MODULATION_PARAMS_OC',
        (0x02, 0x82): 'RADIO_OOK_SET_PKT_PARAMS_OC',
        (0x02, 0x83): 'RADIO_OOK_SET_CRC_PARAMS_OC',
        (0x02, 0x84): 'RADIO_OOK_SET_SYNCWORD_OC',
        (0x02, 0x85): 'RADIO_OOK_SET_ADDRESSES_OC',
        (0x02, 0x86): 'RADIO_OOK_GET_RX_STATISTICS_OC',
        (0x02, 0x87): 'RADIO_OOK_GET_PACKET_STATUS_OC',
        (0x02, 0x88): 'RADIO_OOK_SET_RX_DETECTOR_OC',
        (0x02, 0x89): 'RADIO_OOK_SET_WHITENING_PARAMS_OC',

        (0x02, 0x9F): 'RADIO_OQPSK_15_4_SET_PARAMS_OC',
        (0x02, 0xA0): 'RADIO_OQPSK_15_4_GET_RX_STATS_OC',
        (0x02, 0xA1): 'RADIO_OQPSK_15_4_GET_PKT_STATUS_OC',
        (0x02, 0xA2): 'RADIO_OQPSK_15_4_SET_PAYLOAD_LENGTH_OC',
        (0x02, 0xA3): 'RADIO_OQPSK_15_4_SET_ADDRESSES_OC',

        (0x02, 0x70): 'RADIO_WI_SUN_SET_OPERATING_MODE_OC',
        (0x02, 0x71): 'RADIO_WI_SUN_SET_PKT_PARAMS_OC',
        (0x02, 0x72): 'RADIO_WI_SUN_GET_RX_STATS_OC',
        (0x02, 0x73): 'RADIO_WI_SUN_GET_PKT_STATUS_OC',
        (0x02, 0x74): 'RADIO_WI_SUN_SET_PACKET_LENGTH_OC',

        (0x02, 0x6A): 'RADIO_WM_BUS_SET_PARAMS_OC',
        (0x02, 0x6C): 'RADIO_WM_BUS_GET_RX_STATS_OC',
        (0x02, 0x6D): 'RADIO_WM_BUS_GET_PKT_STATUS_OC',
        (0x02, 0x6E): 'RADIO_WM_BUS_SET_ADDR_OC',

        (0x02, 0x97): 'RADIO_Z_WAVE_SET_PARAMS_OC',
        (0x02, 0x98): 'RADIO_Z_WAVE_SET_HOMEID_OC',
        (0x02, 0x99): 'RADIO_Z_WAVE_GET_RX_STATS_OC',
        (0x02, 0x9A): 'RADIO_Z_WAVE_GET_PKT_STATUS_OC',
        (0x02, 0x9B): 'RADIO_Z_WAVE_SET_BEAM_FILTERING_PARAMS_OC',
        (0x02, 0x9C): 'RADIO_Z_WAVE_SET_SCAN_PARAMS_OC',
        (0x02, 0x9D): 'RADIO_Z_WAVE_SET_SCAN_OC',

        (0x02, 0x78): 'RTTOF_SET_RESPONDER_ADDRESS_OC',
        (0x02, 0x79): 'RTTOF_SET_INITIATOR_ADDRESS_OC',
        (0x02, 0x7A): 'RTTOF_GET_RESULTS_OC',
        (0x02, 0x7B): 'RTTOF_SET_TX_RX_DELAY_OC',
        (0x02, 0x7C): 'RTTOF_SET_PARAMETERS_OC',
        (0x02, 0x7D): 'RTTOF_GET_STATS_OC',
        (0x02, 0x1D): 'RTTOF_CONFIGURE_TIMING_SYNCHRONIZATION_OC',

        (0x01, 0x00): 'SYSTEM_GET_STATUS_OC',
        (0x01, 0x01): 'SYSTEM_GET_VERSION_OC',
        (0x01, 0x10): 'SYSTEM_GET_ERRORS_OC',
        (0x01, 0x11): 'SYSTEM_CLEAR_ERRORS_OC',
        (0x01, 0x12): 'SYSTEM_SET_DIO_FUNC_OC',
        (0x01, 0x13): 'SYSTEM_SET_DIO_RF_SWITCH_CFG_OC',
        (0x01, 0x15): 'SYSTEM_SET_DIO_IRQ_CFG_OC',
        (0x01, 0x16): 'SYSTEM_CLEAR_IRQ_STATUS_OC',
        (0x01, 0x17): 'SYSTEM_GET_AND_CLEAR_IRQ_STATUS_OC',
        (0x01, 0x18): 'SYSTEM_CFG_LF_CLK_OC',
        (0x01, 0x19): 'SYSTEM_CFG_CLK_OUTPUT_OC',
        (0x01, 0x20): 'SYSTEM_SET_TCXO_MODE_OC',
        (0x01, 0x21): 'SYSTEM_SET_REG_MODE_OC',
        (0x01, 0x22): 'SYSTEM_CALIBRATE_OC',
        (0x01, 0x24): 'SYSTEM_GET_VBAT_OC',
        (0x01, 0x25): 'SYSTEM_GET_TEMP_OC',
        (0x01, 0x26): 'SYSTEM_GET_RANDOM_NUMBER_OC',
        (0x01, 0x27): 'SYSTEM_SET_SLEEP_MODE_OC',
        (0x01, 0x28): 'SYSTEM_SET_STANDBY_MODE_OC',
        (0x01, 0x29): 'SYSTEM_SET_FS_MODE_OC',
        (0x01, 0x2A): 'SYSTEM_ADD_REGISTER_TO_RETENTION_MEM_OC',
        (0x01, 0x30): 'SYSTEM_SET_EOL_CFG_OC',
        (0x01, 0x31): 'SYSTEM_CONFIGURE_XOSC_OC',
        (0x01, 0x32): 'SYSTEM_SET_TEMP_COMP_CFG_OC',
        (0x01, 0x33): 'SYSTEM_SET_NTC_PARAMS_OC',

        (0x01, 0x04): 'REGMEM_WRITE_REGMEM32_OC',
        (0x01, 0x05): 'REGMEM_WRITE_REGMEM32_MASK_OC',
        (0x01, 0x06): 'REGMEM_READ_REGMEM32_OC',
        (0x00, 0x00): 'NONE (READ)',
}

# --------------------------------------------------------------------------- #
# LR20xx status flags 
# --------------------------------------------------------------------------- #
STATUS_TABLE = {
    0x00: 'FAIL(0)',
    0x01: 'PERR(1)',
    0x02: 'OK(2)',
    0x03: 'DATA(3)',
}

STATUS_FRAME_TYPE = {
    0: 'lr20xx_fail',
    1: 'lr20xx_perr',
    2: 'lr20xx_ok',
    3: 'lr20xx_data',
}

MODE_TABLE = {
    0x00: 'SLEEP(0)',
    0x01: 'STDBY_RC(1)',
    0x02: 'STDBY_XOSC(2)',
    0x03: 'FS(3)',
    0x04: 'RX(4)',
    0x05: 'TX(5)',
}

RESET_SRC_TABLE = {
    0x00: '',
    0x01: '| RST: Analog(1)',
    0x02: '| RST: NRESET(2)',
    0x03: '| RST: RFU(3)',
}

def _lookup(table, value):
    """Return a human-readable label or a hex fallback."""
    if isinstance(value, tuple):
        fallback = ' '.join(f'0x{b:02X}' for b in value)
        return table.get(value, f'UNKNOWN({fallback})')
    return table.get(value, f'UNKNOWN(0x{value:02X})')


class Hla(HighLevelAnalyzer):
    """
    SPI High Level Analyzer for the LR20xx family.

    Attach this HLA to an SPI analyzer in Logic 2.
    It reads every SPI transaction (enable ↓ … enable ↑) and extracts:
      • command  - first MOSI byte
      • status   - first MISO byte
      • payload  - remaining bytes (MOSI / MISO)
    """

    # Settings:
    enable_int_stat = ChoicesSetting(label='Enable Interrupt Status', choices=['Enable', 'Disable'])
    enable_reset_src = ChoicesSetting(label='Enable Reset Source', choices=['Enable', 'Disable'])
    enable_mode_src = ChoicesSetting(label='Enable Mode Source', choices=['Enable', 'Disable'])

    # ── Result frame types shown in the Logic 2 UI ──────────────────────── #
    # Each type gets its own colour in Logic 2.
    result_types = {
        'lr20xx_fail': {
            'format': '{{data.result}}'
        },
        'lr20xx_perr': {
            'format': '{{data.result}}'
        },
        'lr20xx_ok': {
            'format': '{{data.result}}'
        },
        'lr20xx_data': {
            'format': '{{data.result}}'
        },
        'lr20xx_unknown': {
            'format': '{{data.result}}'
        },
        'lr20xx_spi_error': {
            'format': 'SPI ERROR: {{data.error}}'
        },
    }

    # ── Internal state ──────────────────────────────────────────────────── #
    def __init__(self):
        """Initialise per-transaction accumulators."""
        self._reset()


    def _reset(self):
        """Clear the running transaction state."""
        self.mosi_bytes = []
        self.miso_bytes = []
        self.start_time = None
        self.end_time = None
        self.transaction_active = False

    # ── Frame decoder ───────────────────────────────────────────────────── #
    def decode(self, frame: AnalyzerFrame):
        """
        Called once per SPI frame produced by the lower-level SPI analyser.

        Logic 2 SPI analyser frame types:
          • 'enable'  - CS asserted   (transaction start)
          • 'result'  - one byte transferred (contains 'mosi' and 'miso')
          • 'disable' - CS de-asserted (transaction end)
          • 'error'   - framing error
        """

        # ── CS asserted → start of a new transaction ───────────────────── #
        if frame.type == 'enable':
            self._reset()
            self.transaction_active = True
            self.start_time = frame.start_time
            return None

        # ── CS de-asserted → end of transaction, emit result ───────────── #
        if frame.type == 'disable':
            if not self.transaction_active:
                return None

            self.end_time = frame.end_time
            result = self._build_result()
            self._reset()
            return result

        # ── Data byte ──────────────────────────────────────────────────── #
        if frame.type == 'result':
            if not self.transaction_active:
                return None

            mosi_val = frame.data.get('mosi', b'\x00')
            miso_val = frame.data.get('miso', b'\x00')

            # The SPI analyser may deliver bytes as `bytes` or `int`.
            if isinstance(mosi_val, (bytes, bytearray)):
                self.mosi_bytes.extend(mosi_val)
            else:
                self.mosi_bytes.append(int(mosi_val))

            if isinstance(miso_val, (bytes, bytearray)):
                self.miso_bytes.extend(miso_val)
            else:
                self.miso_bytes.append(int(miso_val))

            self.end_time = frame.end_time
            return None

        # ── Error frame ────────────────────────────────────────────────── #
        if frame.type == 'error':
            return AnalyzerFrame(
                'lr20xx_spi_error',
                frame.start_time,
                frame.end_time,
                {'error': 'SPI framing error'},
            )

        return None

    # ── Result builder ──────────────────────────────────────────────────── #
    def _build_result(self):
        """Assemble a single AnalyzerFrame spanning the full transaction."""
        if len(self.mosi_bytes) < 2:
            return None

        command_key = (self.mosi_bytes[0], self.mosi_bytes[1])
        status_byte_0 = self.miso_bytes[0] if self.miso_bytes else 0x00
        status_byte_1 = self.miso_bytes[1] if len(self.miso_bytes) > 1 else 0x00

        command_status = status_byte_0 >> 1 & 3
        mode = status_byte_1 & 0x07
        reset_src = (status_byte_1 >> 4) & 0x0F
        interrupt = status_byte_0 & 0x01

        frame_type = STATUS_FRAME_TYPE.get(command_status, 'lr20xx_unknown')
        command_str = _lookup(COMMAND_TABLE, command_key)
        command_status_str = _lookup(STATUS_TABLE, command_status)
        mode_str = _lookup(MODE_TABLE, mode)
        reset_src_str = _lookup(RESET_SRC_TABLE, reset_src)
        interrupt_str = '| INT_ACTIVE' if interrupt else ''

        result = f'CMD: {command_str} | STAT: {command_status_str} | MODE: {mode_str} {interrupt_str} {reset_src_str}'

        return AnalyzerFrame(
            frame_type,
            self.start_time,
            self.end_time,
            {
                'result': result
            },
        )
