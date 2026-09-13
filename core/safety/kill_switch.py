"""
HunterAI Emergency Kill Switch
==============================
Global singleton allowing immediate emergency termination of:
- All active browser sessions
- All HTTP dispatchers and sockets
- All queued tasks and background workers
Saves in-flight state to emergency_save.json.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hunter_ai.kill_switch")


class EmergencyKillSwitch:
    """Global singleton emergency kill switch"""
    _instance: Optional[EmergencyKillSwitch] = None

    def __new__(cls) -> EmergencyKillSwitch:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._is_tripped = False
            cls._instance._trip_reason = ""
            cls._instance._registered_teardowns = []
        return cls._instance

    @property
    def is_tripped(self) -> bool:
        return self._is_tripped

    def register_teardown(self, callback: Callable[[], None], name: str = "worker"):
        self._registered_teardowns.append((name, callback))

    def trigger(self, reason: str = "Manual Emergency Abort", save_dir: Optional[Path] = None) -> Dict[str, Any]:
        self._is_tripped = True
        self._trip_reason = reason
        logger.critical(f"🛑 [EMERGENCY KILL SWITCH TRIPPED]: {reason}")

        teardown_results = []
        for name, fn in self._registered_teardowns:
            try:
                fn()
                teardown_results.append({"name": name, "status": "TERMINATED"})
            except Exception as e:
                teardown_results.append({"name": name, "status": f"ERROR: {e}"})

        # Save emergency state
        save_path = (save_dir or Path(".")) / "emergency_save.json"
        state = {
            "kill_switch_tripped": True,
            "reason": reason,
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            "teardowns": teardown_results
        }
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save emergency state: {e}")

        return state

    def reset(self):
        """Resets the kill switch for testing purposes"""
        self._is_tripped = False
        self._trip_reason = ""
