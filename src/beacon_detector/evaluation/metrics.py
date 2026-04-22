from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConfusionMatrix:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0


@dataclass(frozen=True, slots=True)
class ClassificationMetrics:
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    confusion_matrix: ConfusionMatrix


@dataclass(frozen=True, slots=True)
class MetricSpread:
    mean_precision: float
    std_precision: float
    mean_recall: float
    std_recall: float
    mean_f1_score: float
    std_f1_score: float
    mean_false_positive_rate: float
    std_false_positive_rate: float


def calculate_classification_metrics(
    true_labels: list[str],
    predicted_labels: list[str],
    positive_label: str = "beacon",
) -> ClassificationMetrics:
    if len(true_labels) != len(predicted_labels):
        raise ValueError("true_labels and predicted_labels must have the same length.")

    tp = fp = tn = fn = 0
    for true_label, predicted_label in zip(true_labels, predicted_labels, strict=True):
        is_positive = true_label == positive_label
        predicted_positive = predicted_label == positive_label
        if is_positive and predicted_positive:
            tp += 1
        elif not is_positive and predicted_positive:
            fp += 1
        elif not is_positive and not predicted_positive:
            tn += 1
        else:
            fn += 1

    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1_score = _safe_divide(2 * precision * recall, precision + recall)
    false_positive_rate = _safe_divide(fp, fp + tn)

    return ClassificationMetrics(
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        false_positive_rate=false_positive_rate,
        confusion_matrix=ConfusionMatrix(
            true_positive=tp,
            false_positive=fp,
            true_negative=tn,
            false_negative=fn,
        ),
    )


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def summarize_metric_spread(metrics: list[ClassificationMetrics]) -> MetricSpread:
    return MetricSpread(
        mean_precision=_mean([metric.precision for metric in metrics]),
        std_precision=_std([metric.precision for metric in metrics]),
        mean_recall=_mean([metric.recall for metric in metrics]),
        std_recall=_std([metric.recall for metric in metrics]),
        mean_f1_score=_mean([metric.f1_score for metric in metrics]),
        std_f1_score=_std([metric.f1_score for metric in metrics]),
        mean_false_positive_rate=_mean(
            [metric.false_positive_rate for metric in metrics]
        ),
        std_false_positive_rate=_std(
            [metric.false_positive_rate for metric in metrics]
        ),
    )


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean_value = _mean(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    return variance**0.5
