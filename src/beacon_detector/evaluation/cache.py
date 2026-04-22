from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal

from beacon_detector.data import SyntheticTrafficConfig
from beacon_detector.features import FlowFeatures
from beacon_detector.flows import FlowKey

FEATURE_CACHE_VERSION = "feature_cache_v1"
FEATURE_SCHEMA_VERSION = "flow_features_v3"

CacheStatus = Literal["disabled", "hit", "miss", "stale"]


@dataclass(frozen=True, slots=True)
class FeatureCacheConfig:
    enabled: bool = True
    cache_dir: Path = Path("results/cache/features")
    mode: str = "full"
    cache_version: str = FEATURE_CACHE_VERSION
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    verbose: bool = True


@dataclass(frozen=True, slots=True)
class FeatureCacheResult:
    rows: list[FlowFeatures]
    status: CacheStatus
    path: Path | None


def get_or_build_feature_rows(
    *,
    cache_config: FeatureCacheConfig | None,
    cache_kind: str,
    cache_name: str,
    seed: int,
    source_config: SyntheticTrafficConfig,
    build_rows: Callable[[], list[FlowFeatures]],
) -> FeatureCacheResult:
    if cache_config is None:
        return FeatureCacheResult(rows=build_rows(), status="disabled", path=None)
    if not cache_config.enabled:
        _log(cache_config, "feature-cache bypassed")
        return FeatureCacheResult(rows=build_rows(), status="disabled", path=None)

    metadata = _metadata(
        cache_config=cache_config,
        cache_kind=cache_kind,
        cache_name=cache_name,
        seed=seed,
        source_config=source_config,
    )
    path = _cache_path(cache_config, metadata)
    cached_rows, status = _load_feature_rows(path, cache_config, metadata)
    if cached_rows is not None:
        _log(cache_config, f"feature-cache hit {path}")
        return FeatureCacheResult(rows=cached_rows, status="hit", path=path)

    _log(cache_config, f"feature-cache {status} {path}")
    rows = build_rows()
    _write_feature_rows(path, cache_config, metadata, rows)
    _log(cache_config, f"feature-cache written {path}")
    return FeatureCacheResult(rows=rows, status=status, path=path)


def _metadata(
    *,
    cache_config: FeatureCacheConfig,
    cache_kind: str,
    cache_name: str,
    seed: int,
    source_config: SyntheticTrafficConfig,
) -> dict[str, str | int]:
    config_hash = stable_config_hash(source_config)
    return {
        "cache_kind": cache_kind,
        "cache_name": cache_name,
        "mode": cache_config.mode,
        "seed": seed,
        "config_hash": config_hash,
    }


def stable_config_hash(config: SyntheticTrafficConfig) -> str:
    payload = json.dumps(_normalize(asdict(config)), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _cache_path(cache_config: FeatureCacheConfig, metadata: dict[str, str | int]) -> Path:
    safe_name = _safe_filename(str(metadata["cache_name"]))
    filename = (
        f"{metadata['cache_kind']}_{metadata['mode']}_{safe_name}_"
        f"seed{metadata['seed']}_{metadata['config_hash']}_"
        f"{cache_config.feature_schema_version}.json"
    )
    return Path(cache_config.cache_dir) / filename


def _load_feature_rows(
    path: Path,
    cache_config: FeatureCacheConfig,
    expected_metadata: dict[str, str | int],
) -> tuple[list[FlowFeatures] | None, CacheStatus]:
    if not path.exists():
        return None, "miss"

    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, "stale"

    if envelope.get("cache_version") != cache_config.cache_version:
        return None, "stale"
    if envelope.get("feature_schema_version") != cache_config.feature_schema_version:
        return None, "stale"
    if envelope.get("feature_fields") != _feature_fields():
        return None, "stale"
    if envelope.get("metadata") != expected_metadata:
        return None, "stale"

    return [_feature_row_from_dict(row) for row in envelope.get("rows", [])], "hit"


def _write_feature_rows(
    path: Path,
    cache_config: FeatureCacheConfig,
    metadata: dict[str, str | int],
    rows: list[FlowFeatures],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    envelope = {
        "cache_version": cache_config.cache_version,
        "feature_schema_version": cache_config.feature_schema_version,
        "feature_fields": _feature_fields(),
        "metadata": metadata,
        "rows": [_feature_row_to_dict(row) for row in rows],
    }
    path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")


def _feature_row_to_dict(row: FlowFeatures) -> dict:
    return asdict(row)


def _feature_row_from_dict(payload: dict) -> FlowFeatures:
    row_payload = dict(payload)
    row_payload["flow_key"] = FlowKey(**row_payload["flow_key"])
    return FlowFeatures(**row_payload)


def _feature_fields() -> list[str]:
    return [field.name for field in fields(FlowFeatures)]


def _safe_filename(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in value
    )


def _normalize(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _normalize(asdict(value))
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_normalize(item) for item in value]
    return value


def _log(cache_config: FeatureCacheConfig, message: str) -> None:
    if cache_config.verbose:
        print(message)
