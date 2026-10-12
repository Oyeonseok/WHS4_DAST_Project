from __future__ import annotations

from aidast.recon.strix_engine.runtime.docker_client import (
    _IMAGE_ENTRYPOINT_PATH,
    _apply_integrated_entrypoint,
)


def test_integrated_proxy_mounts_packaged_entrypoint() -> None:
    create_kwargs: dict[str, object] = {}

    _apply_integrated_entrypoint(
        create_kwargs,
        {"STRIX_PROXY_BACKEND": "mitmproxy"},
    )

    assert create_kwargs["entrypoint"] == ["/bin/bash", _IMAGE_ENTRYPOINT_PATH]
    mount = create_kwargs["mounts"][0]
    assert mount["Target"] == _IMAGE_ENTRYPOINT_PATH
    assert mount["ReadOnly"] is True


def test_caido_mode_keeps_image_entrypoint() -> None:
    create_kwargs: dict[str, object] = {}

    _apply_integrated_entrypoint(
        create_kwargs,
        {"STRIX_PROXY_BACKEND": "caido"},
    )

    assert create_kwargs == {}
