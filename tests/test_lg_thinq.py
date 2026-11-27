from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from pi_probe_discord.lg_thinq import collect_lg_thinq_snapshot, load_lg_thinq_state
from tests.test_dashboard import make_config


class _Response:
    ok = True
    status_code = 200

    def __init__(self, response: object) -> None:
        self._response = response

    def json(self) -> dict[str, object]:
        return {"response": self._response}


class LGThinQTests(unittest.TestCase):
    def test_collects_refrigerator_without_persisting_pat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = replace(
                make_config(root),
                lg_thinq_enabled=True,
                lg_thinq_device_model="GF-VN600BM",
                lg_thinq_state_json=str(root / "lg-thinq" / "latest.json"),
            )
            responses = iter([
                _Response([{"deviceId": "fridge-1", "deviceInfo": {"deviceType": "DEVICE_REFRIGERATOR", "alias": "Kitchen fridge", "modelName": "GF-VN600BM"}}]),
                _Response({"doorStatus": [{"locationName": "MAIN", "doorState": "CLOSE"}], "temperature": [{"locationName": "FRIDGE", "targetTemperature": 3, "unit": "C"}], "refrigeration": {"expressMode": False, "freshAirFilter": "AUTO"}}),
            ])
            with patch.dict(os.environ, {"PI_PROBE_LG_THINQ_PAT": "pat-secret"}, clear=False), patch("pi_probe_discord.lg_thinq.requests.get", side_effect=lambda *args, **kwargs: next(responses)):
                snapshot = collect_lg_thinq_snapshot(config)
            self.assertTrue(snapshot["available"])
            self.assertEqual(snapshot["device"]["name"], "Kitchen fridge")
            self.assertEqual(snapshot["status"]["doors"], ["MAIN: Close"])
            persisted = (root / "lg-thinq" / "latest.json").read_text(encoding="utf-8")
            self.assertNotIn("pat-secret", persisted)
            self.assertEqual(load_lg_thinq_state(config)["status"]["temperatures"], ["FRIDGE: 3 °C"])

