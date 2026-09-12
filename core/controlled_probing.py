"""
Controlled Probing Engine
=========================
Enforces the scientific testing contract:
BASELINE -> CONTROL -> TEST -> COMPARE -> REPEAT
Rules out dynamic page noise, caching, and transient server errors before formulating findings.
"""
from dataclasses import dataclass
from typing import Callable, Awaitable, Dict, Any, Tuple
from core.response_fingerprinter import ResponseFingerprinter, ResponseFingerprint


@dataclass
class ProbeCycleResult:
    is_valid_deviation: bool
    deviation_reason: str
    baseline_fp: ResponseFingerprint
    control_fp: ResponseFingerprint
    test_fp: ResponseFingerprint
    repeat_confirmed: bool


class ControlledProbingEngine:
    """Executes controlled probes with baseline, negative control, and repeat verification"""

    @classmethod
    async def execute_probe_cycle(
        cls,
        probe_fn: Callable[[str], Awaitable[Tuple[int, str, Dict[str, str], float]]],
        param_name: str,
        baseline_val: str,
        negative_control_val: str,
        test_payload_val: str
    ) -> ProbeCycleResult:
        # 1. Baseline
        b_code, b_body, b_hdr, b_time = await probe_fn(baseline_val)
        base_fp = ResponseFingerprinter.fingerprint(b_code, b_body, b_hdr, b_time)

        # 2. Negative Control (benign distinct input e.g. "normal_val_982")
        c_code, c_body, c_hdr, c_time = await probe_fn(negative_control_val)
        ctrl_fp = ResponseFingerprinter.fingerprint(c_code, c_body, c_hdr, c_time)

        # Check if page is wildly erratic between baseline and control
        if base_fp.status_code != ctrl_fp.status_code:
            return ProbeCycleResult(
                is_valid_deviation=False,
                deviation_reason="Page response is inherently unstable between baseline and negative control.",
                baseline_fp=base_fp, control_fp=ctrl_fp, test_fp=ctrl_fp, repeat_confirmed=False
            )

        # 3. Test with active payload
        t_code, t_body, t_hdr, t_time = await probe_fn(test_payload_val)
        test_fp = ResponseFingerprinter.fingerprint(t_code, t_body, t_hdr, t_time)

        # 4. Compare Test against Control
        is_dev, reason = ResponseFingerprinter.is_meaningful_deviation(ctrl_fp, test_fp)
        if not is_dev:
            return ProbeCycleResult(
                is_valid_deviation=False,
                deviation_reason=f"No meaningful deviation from control: {reason}",
                baseline_fp=base_fp, control_fp=ctrl_fp, test_fp=test_fp, repeat_confirmed=False
            )

        # 5. Repeat: Re-test to confirm reproducibility
        r_code, r_body, r_hdr, r_time = await probe_fn(test_payload_val)
        repeat_fp = ResponseFingerprinter.fingerprint(r_code, r_body, r_hdr, r_time)
        reproduced = (repeat_fp.status_code == test_fp.status_code) and (repeat_fp.dom_skeleton_hash == test_fp.dom_skeleton_hash)

        return ProbeCycleResult(
            is_valid_deviation=True,
            deviation_reason=reason,
            baseline_fp=base_fp,
            control_fp=ctrl_fp,
            test_fp=test_fp,
            repeat_confirmed=reproduced
        )