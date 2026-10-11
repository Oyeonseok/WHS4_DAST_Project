"""Repeat the approved Juice Shop Recon with the prior four ffuf roots.

The selector calls an external model and can fail over to many more roots.
Pinning its previous result keeps the GET-detail comparison bounded.
"""

from __future__ import annotations

import runpy
from unittest.mock import patch


with patch(
    "aidast.recon.tools.endpoint_discovery.select_ffuf_roots_from_endpoints",
    return_value=["/", "/api", "/rest", "/socket.io"],
):
    runpy.run_path(
        "docs/test-results/09.24/_archive/recon_with_pinned_policy.py",
        run_name="__main__",
    )
