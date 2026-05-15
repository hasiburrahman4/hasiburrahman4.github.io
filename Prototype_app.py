# Prototype app for the ATC Phase 4 demonstrator.
# This interactive Streamlit UI runs the same ASI-PLC simulation logic as Prototype.py
# and is intended for exploratory analysis and design validation.
# It is not a substitute for field deployment or an empirical hardware test.
import hashlib
import hmac as hmac_lib
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import streamlit as st

sns.set_style('whitegrid')


class PLCState(Enum):
    IDLE = 'IDLE'
    COMPLIANT = 'COMPLIANT'
    NON_COMPLIANT = 'NON_COMPLIANT'
    SOFT_LOCK = 'SOFT_LOCK'
    HARD_LOCK = 'HARD_LOCK'


class FaultType(Enum):
    NONE = 'none'
    NON_COMPLY = 'non_comply'
    MITM = 'mitm'
    REPLAY = 'replay'
    TIMEOUT = 'timeout'


@dataclass
class OraclePayload:
    compliant_flag: bool
    failure_reason: str
    weld_id: str
    timestamp_utc: int
    nonce: int
    latency_ms: float
    hmac_sig: str
    asym_sig: str


@dataclass
class PLCCycleResult:
    scenario_id: int
    fault_type: FaultType
    payload: OraclePayload
    state: PLCState
    compliance_bit: bool
    relay_on: bool
    latency_ms: float
    step_failures: List[str] = field(default_factory=list)


class ASI_PLC:
    HEARTBEAT_TIMEOUT_MS = 500.0
    GATEWAY_KEY = b'ATC-QBFT-Besu-OracleKey-TuL-2025'

    def __init__(self):
        self._state = PLCState.IDLE
        self._last_heartbeat = 0.0
        self._last_nonce = 0
        self._hard_lock = False
        self._soft_lock = False
        self._compliance_bit = False
        self._cycle_clock_ms = 0.0

    @property
    def state(self) -> PLCState:
        return self._state

    @property
    def compliance_bit(self) -> bool:
        return self._compliance_bit

    @property
    def relay_on(self) -> bool:
        return self._compliance_bit

    def admin_reset(self):
        self._hard_lock = False
        self._compliance_bit = False
        self._state = PLCState.IDLE

    def _compute_hmac(self, payload: OraclePayload) -> str:
        data = json.dumps({
            'compliant': payload.compliant_flag,
            'reason': payload.failure_reason,
            'weld_id': payload.weld_id,
            'ts': payload.timestamp_utc,
            'nonce': payload.nonce,
        }, sort_keys=True).encode()
        return hmac_lib.new(self.GATEWAY_KEY, data, hashlib.sha256).hexdigest()

    def process_cycle(self, payload: OraclePayload) -> Tuple[PLCState, List[str]]:
        failures = []
        self._cycle_clock_ms += self.HEARTBEAT_TIMEOUT_MS

        elapsed = payload.latency_ms
        if elapsed > self.HEARTBEAT_TIMEOUT_MS:
            self._soft_lock = True
            self._compliance_bit = False
            self._state = PLCState.SOFT_LOCK
            failures.append(f"STEP1_HEARTBEAT_TIMEOUT ({elapsed:.1f}ms > 500ms)")
            return self._state, failures

        if payload.nonce <= self._last_nonce:
            self._hard_lock = True
            self._compliance_bit = False
            self._state = PLCState.HARD_LOCK
            failures.append(f"STEP2_NONCE_REPLAY (rcv={payload.nonce} ≤ last={self._last_nonce})")
            return self._state, failures

        expected_hmac = self._compute_hmac(payload)
        if payload.hmac_sig != expected_hmac:
            self._hard_lock = True
            self._compliance_bit = False
            self._state = PLCState.HARD_LOCK
            failures.append('STEP3_HMAC_INVALID (MitM attack detected)')
            return self._state, failures

        expected_asym = hashlib.sha256(expected_hmac.encode()).hexdigest()
        if payload.asym_sig != expected_asym:
            self._hard_lock = True
            self._compliance_bit = False
            self._state = PLCState.HARD_LOCK
            failures.append('STEP4_ASYM_SIG_INVALID (Oracle identity unverified)')
            return self._state, failures

        self._soft_lock = False
        self._last_heartbeat = self._cycle_clock_ms
        self._last_nonce = payload.nonce
        self._compliance_bit = payload.compliant_flag and (not self._hard_lock)
        self._state = PLCState.COMPLIANT if self._compliance_bit else PLCState.NON_COMPLIANT
        return self._state, failures


class OracleGateway:
    MEAN_LATENCY_MS = 275.2
    STD_LATENCY_MS = 25.0
    TIMEOUT_MEAN_MS = 514.6
    TIMEOUT_STD_MS = 20.0
    GATEWAY_KEY = b'ATC-QBFT-Besu-OracleKey-TuL-2025'

    def __init__(self, rng: np.random.Generator):
        self._rng = rng
        self._nonce = 0

    def build_payload(self, compliant: bool, reason: str, fault: FaultType) -> OraclePayload:
        self._nonce += 1
        ts = int(time.time())
        weld_id = secrets.token_hex(8)
        nonce = 1 if fault == FaultType.REPLAY else self._nonce

        if fault == FaultType.TIMEOUT:
            latency = float(self._rng.normal(self.TIMEOUT_MEAN_MS, self.TIMEOUT_STD_MS))
        else:
            latency = float(self._rng.normal(self.MEAN_LATENCY_MS, self.STD_LATENCY_MS))

        body = json.dumps({
            'compliant': compliant,
            'reason': reason,
            'weld_id': weld_id,
            'ts': ts,
            'nonce': nonce,
        }, sort_keys=True).encode()

        hmac_sig = hmac_lib.new(self.GATEWAY_KEY, body, hashlib.sha256).hexdigest()
        asym_sig = hashlib.sha256(hmac_sig.encode()).hexdigest()
        if fault == FaultType.MITM:
            hmac_sig = secrets.token_hex(32)

        return OraclePayload(
            compliant_flag=compliant,
            failure_reason=reason,
            weld_id=weld_id,
            timestamp_utc=ts,
            nonce=nonce,
            latency_ms=latency,
            hmac_sig=hmac_sig,
            asym_sig=asym_sig,
        )


def run_simulation(seed: int, scenario_plan: List[Tuple[int, FaultType, bool, str]]):
    rng = np.random.default_rng(seed)
    oracle = OracleGateway(rng)
    plc = ASI_PLC()
    results: List[PLCCycleResult] = []
    scenario_id = 0

    for count, fault, compliant, reason in scenario_plan:
        for _ in range(count):
            if fault == FaultType.REPLAY and len(results) > 0:
                plc.admin_reset()
            payload = oracle.build_payload(compliant, reason, fault)
            if fault in (FaultType.MITM, FaultType.REPLAY) and plc.state == PLCState.HARD_LOCK:
                plc.admin_reset()
            state, failures = plc.process_cycle(payload)
            results.append(PLCCycleResult(
                scenario_id=scenario_id,
                fault_type=fault,
                payload=payload,
                state=state,
                compliance_bit=plc.compliance_bit,
                relay_on=plc.relay_on,
                latency_ms=payload.latency_ms,
                step_failures=failures,
            ))
            scenario_id += 1

    return results


def summarize_results(results: List[PLCCycleResult]):
    valid_results = [r for r in results if r.fault_type == FaultType.NONE]
    noncomply_results = [r for r in results if r.fault_type == FaultType.NON_COMPLY]
    mitm_results = [r for r in results if r.fault_type == FaultType.MITM]
    replay_results = [r for r in results if r.fault_type == FaultType.REPLAY]
    timeout_results = [r for r in results if r.fault_type == FaultType.TIMEOUT]

    valid_latencies = np.array([r.latency_ms for r in valid_results])
    timeout_latencies = np.array([r.latency_ms for r in timeout_results])

    total_false_positives = sum(1 for r in noncomply_results + mitm_results + replay_results if r.compliance_bit)
    total_false_negatives = sum(1 for r in valid_results if not r.compliance_bit)

    state_counts = {
        state.value: sum(1 for r in results if r.state == state)
        for state in PLCState
    }

    return {
        'valid_results': valid_results,
        'noncomply_results': noncomply_results,
        'mitm_results': mitm_results,
        'replay_results': replay_results,
        'timeout_results': timeout_results,
        'valid_latencies': valid_latencies,
        'timeout_latencies': timeout_latencies,
        'false_positives': total_false_positives,
        'false_negatives': total_false_negatives,
        'state_counts': state_counts,
    }


def plot_latency_histogram(latencies):
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(latencies, bins=25, color='#2E7D32', edgecolor='white', alpha=0.8)
    ax.set_title('Valid Scenario Latency Distribution')
    ax.set_xlabel('Latency (ms)')
    ax.set_ylabel('Count')
    return fig


def plot_state_distribution(state_counts):
    names = list(state_counts.keys())
    values = list(state_counts.values())
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, values, color=['#2E7D32', '#C62828', '#E65100', '#4A148C', '#455A64'])
    ax.set_title('PLC State Distribution')
    ax.set_ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    return fig


def app():
    st.set_page_config(page_title='ATC Phase 4 Prototype', layout='wide')
    st.title('ATC Phase 4 — ASI-PLC Simulator')
    st.write('Interactive prototype for the ASI-PLC safety state machine and attack scenarios.')

    with st.sidebar:
        st.header('Simulation controls')
        seed = st.number_input('Random seed', min_value=0, value=2025, step=1)
        n_valid = st.number_input('Valid scenarios', min_value=0, value=120, step=10)
        n_noncomply = st.number_input('Non-compliant scenarios', min_value=0, value=50, step=10)
        n_mitm = st.number_input('MitM attack scenarios', min_value=0, value=10, step=5)
        n_replay = st.number_input('Replay attack scenarios', min_value=0, value=10, step=5)
        n_timeout = st.number_input('Timeout scenarios', min_value=0, value=10, step=5)
        st.write('---')
        run_button = st.button('Run simulation')

    scenario_plan = [
        (n_valid, FaultType.NONE, True, 'COMPLIANT'),
        (n_noncomply, FaultType.NON_COMPLY, False, 'PREHEAT_BELOW_MINIMUM'),
        (n_mitm, FaultType.MITM, True, 'COMPLIANT'),
        (n_replay, FaultType.REPLAY, True, 'COMPLIANT'),
        (n_timeout, FaultType.TIMEOUT, True, 'COMPLIANT'),
    ]

    if run_button:
        with st.spinner('Running simulation...'):
            results = run_simulation(seed, scenario_plan)
            summary = summarize_results(results)

        st.success('Simulation complete')

        col1, col2 = st.columns(2)
        col1.metric('Total scenarios', len(results))
        col1.metric('False positives', summary['false_positives'])
        col1.metric('False negatives', summary['false_negatives'])
        col2.metric('Valid results', len(summary['valid_results']))
        col2.metric('Soft lock count', len(summary['timeout_results']))
        col2.metric('Hard lock events', len([r for r in results if r.state == PLCState.HARD_LOCK]))

        st.pyplot(plot_latency_histogram(summary['valid_latencies']))
        st.pyplot(plot_state_distribution(summary['state_counts']))

        st.subheader('Scenario details')
        first_table = [
            {
                'idx': r.scenario_id,
                'fault': r.fault_type.value,
                'state': r.state.value,
                'relay_on': r.relay_on,
                'latency_ms': f'{r.latency_ms:.1f}',
                'failures': '; '.join(r.step_failures),
            }
            for r in results[:30]
        ]
        st.table(first_table)

        st.subheader('Full state counts')
        st.json(summary['state_counts'])
    else:
        st.info('Adjust the controls and click Run simulation to launch the prototype.')


if __name__ == '__main__':
    app()
