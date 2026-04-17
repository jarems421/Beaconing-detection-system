from __future__ import annotations

from collections import Counter

from .runner import EvaluationSummary, PredictionRecord


def top_false_positives(
    summary: EvaluationSummary,
    limit: int = 10,
) -> list[PredictionRecord]:
    records = [
        record
        for record in summary.records
        if record.true_label == "benign" and record.predicted_label == "beacon"
    ]
    return sorted(records, key=lambda record: record.score, reverse=True)[:limit]


def top_false_negatives(
    summary: EvaluationSummary,
    limit: int = 10,
) -> list[PredictionRecord]:
    records = [
        record
        for record in summary.records
        if record.true_label == "beacon" and record.predicted_label == "benign"
    ]
    return sorted(records, key=lambda record: record.score)[:limit]


def score_distribution(
    records: tuple[PredictionRecord, ...],
    label: str | None = None,
    bucket_size: float = 0.5,
) -> dict[float, int]:
    if bucket_size <= 0:
        raise ValueError("bucket_size must be positive.")

    selected_records = [
        record for record in records if label is None or record.true_label == label
    ]
    buckets = Counter(
        round((record.score // bucket_size) * bucket_size, 3)
        for record in selected_records
    )
    return dict(sorted(buckets.items()))

