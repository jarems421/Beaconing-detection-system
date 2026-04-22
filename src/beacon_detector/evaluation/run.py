from __future__ import annotations

import argparse
from dataclasses import replace

from beacon_detector.detection import (
    FROZEN_RULE_BASELINE_NAME,
    FROZEN_RULE_BASELINE_THRESHOLDS,
    ISOLATION_FOREST_NAME,
    LOCAL_OUTLIER_FACTOR_NAME,
    LOGISTIC_REGRESSION_NAME,
    RANDOM_FOREST_NAME,
    STATISTICAL_BASELINE_NAME,
    AnomalyDetectorConfig,
    StatisticalBaselineConfig,
    SupervisedDetectorConfig,
    supervised_operating_point,
)
from beacon_detector.evaluation import (
    FROZEN_BASELINE_SEEDS,
    OPERATING_POINT_THRESHOLDS,
    QUICK_EVALUATION_SEEDS,
    FeatureCacheConfig,
    build_default_evaluation_grid,
    build_quick_evaluation_grid,
    evaluate_anomaly_detector_multi_seed,
    evaluate_rule_detector,
    evaluate_rule_detector_multi_seed,
    evaluate_statistical_detector_multi_seed,
    evaluate_supervised_detector_multi_seed,
    export_experiment_tables,
    sweep_prediction_thresholds,
    sweep_prediction_thresholds_multi_seed,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the rule-based beaconing detector evaluation."
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=None,
        help="Seeds used for multi-seed evaluation.",
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=float,
        default=list(OPERATING_POINT_THRESHOLDS),
        help="Prediction thresholds to compare.",
    )
    parser.add_argument(
        "--export-results",
        action="store_true",
        help="Write CSV/JSON experiment tables under results/tables/.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Use a small explicit case/seed subset for fast sanity checks.",
    )
    parser.add_argument(
        "--output-dir",
        default="results/tables",
        help="Directory for exported result tables.",
    )
    parser.add_argument(
        "--cache-dir",
        default="results/cache/features",
        help="Directory for cached feature rows.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable feature-row caching for this run.",
    )
    args = parser.parse_args()

    seeds = tuple(
        args.seeds
        if args.seeds is not None
        else (QUICK_EVALUATION_SEEDS if args.quick else FROZEN_BASELINE_SEEDS)
    )
    cases = build_quick_evaluation_grid() if args.quick else build_default_evaluation_grid()
    cache_config = FeatureCacheConfig(
        enabled=not args.no_cache,
        cache_dir=args.cache_dir,
        mode="quick" if args.quick else "full",
        verbose=True,
    )
    summary = evaluate_rule_detector(cases, cache_config=cache_config)
    multi_seed_summary = evaluate_rule_detector_multi_seed(
        seeds,
        cases=cases,
        cache_config=cache_config,
    )
    threshold_results = sweep_prediction_thresholds(
        args.thresholds,
        cases=cases,
        cache_config=cache_config,
    )
    multi_seed_threshold_results = sweep_prediction_thresholds_multi_seed(
        args.thresholds,
        seeds=seeds,
        cases=cases,
        cache_config=cache_config,
    )

    _print_overall(summary)
    _print_per_case(summary)
    _print_per_scenario(summary)
    _print_multi_seed(multi_seed_summary)
    _print_threshold_sweep(threshold_results)
    _print_multi_seed_threshold_sweep(multi_seed_threshold_results)

    if args.export_results:
        statistical_config = StatisticalBaselineConfig()
        anomaly_config = AnomalyDetectorConfig()
        supervised_config = SupervisedDetectorConfig()
        rule_operating_summary = _summary_for_threshold(
            multi_seed_threshold_results,
            threshold=2.8,
        ) or evaluate_rule_detector_multi_seed(
            seeds,
            thresholds=replace(
                FROZEN_RULE_BASELINE_THRESHOLDS,
                prediction_threshold=2.8,
            ),
            cases=cases,
            cache_config=cache_config,
        )
        statistical_summary = evaluate_statistical_detector_multi_seed(
            seeds,
            config=statistical_config,
            cases=cases,
            cache_config=cache_config,
        )
        isolation_forest_summary = evaluate_anomaly_detector_multi_seed(
            "isolation_forest",
            seeds=seeds,
            config=anomaly_config,
            cases=cases,
            cache_config=cache_config,
        )
        lof_summary = evaluate_anomaly_detector_multi_seed(
            "local_outlier_factor",
            seeds=seeds,
            config=anomaly_config,
            cases=cases,
            cache_config=cache_config,
        )
        logistic_summary = evaluate_supervised_detector_multi_seed(
            "logistic_regression",
            seeds=seeds,
            config=supervised_config,
            cases=cases,
            training_cases=cases,
            cache_config=cache_config,
        )
        random_forest_summary = evaluate_supervised_detector_multi_seed(
            "random_forest",
            seeds=seeds,
            config=supervised_config,
            cases=cases,
            training_cases=cases,
            cache_config=cache_config,
        )
        baseline_summaries = {
            FROZEN_RULE_BASELINE_NAME: rule_operating_summary,
            STATISTICAL_BASELINE_NAME: statistical_summary,
            ISOLATION_FOREST_NAME: isolation_forest_summary,
            LOCAL_OUTLIER_FACTOR_NAME: lof_summary,
            LOGISTIC_REGRESSION_NAME: logistic_summary,
            RANDOM_FOREST_NAME: random_forest_summary,
        }
        _print_detector_comparison(baseline_summaries)
        written_paths = export_experiment_tables(
            output_dir=args.output_dir,
            baseline_summaries=baseline_summaries,
            threshold_results=multi_seed_threshold_results,
            cases=cases,
            seeds=seeds,
            rule_operating_threshold=2.8,
            statistical_config=statistical_config,
            anomaly_config=anomaly_config,
            supervised_config=supervised_config,
            detector_operating_points={
                LOGISTIC_REGRESSION_NAME: supervised_operating_point(
                    supervised_config
                ),
                RANDOM_FOREST_NAME: supervised_operating_point(supervised_config),
            },
        )
        print("\nExported Result Tables")
        for path in written_paths:
            print(path)


def _print_overall(summary) -> None:
    metrics = summary.overall_metrics
    matrix = metrics.confusion_matrix
    print("Overall")
    print(
        f"precision={metrics.precision:.4f} "
        f"recall={metrics.recall:.4f} "
        f"f1={metrics.f1_score:.4f} "
        f"fpr={metrics.false_positive_rate:.4f}"
    )
    print(
        f"confusion_matrix tp={matrix.true_positive} fp={matrix.false_positive} "
        f"tn={matrix.true_negative} fn={matrix.false_negative}"
    )


def _print_per_case(summary) -> None:
    print("\nPer Case")
    for row in summary.per_case_metrics:
        metrics = row.metrics
        matrix = metrics.confusion_matrix
        print(
            f"{row.case_name}: flows={row.total_flows} "
            f"precision={metrics.precision:.4f} recall={metrics.recall:.4f} "
            f"f1={metrics.f1_score:.4f} fpr={metrics.false_positive_rate:.4f} "
            f"fp={matrix.false_positive} fn={matrix.false_negative}"
        )


def _print_per_scenario(summary) -> None:
    print("\nPer Scenario")
    for row in summary.per_scenario_rates:
        print(
            f"{row.scenario_name}: flows={row.total_flows} "
            f"true_beacons={row.true_beacon_flows} "
            f"predicted_beacons={row.predicted_beacon_flows} "
            f"rate={row.detection_rate:.4f}"
        )


def _print_multi_seed(summary) -> None:
    spread = summary.metric_spread
    print("\nMulti-Seed")
    print(
        f"precision={spread.mean_precision:.4f}+/-{spread.std_precision:.4f} "
        f"recall={spread.mean_recall:.4f}+/-{spread.std_recall:.4f} "
        f"f1={spread.mean_f1_score:.4f}+/-{spread.std_f1_score:.4f} "
        f"fpr={spread.mean_false_positive_rate:.4f}+/-"
        f"{spread.std_false_positive_rate:.4f}"
    )
    print("Combined Multi-Seed")
    _print_overall(summary.combined_summary)


def _print_threshold_sweep(results) -> None:
    print("\nThreshold Sweep")
    for result in results:
        metrics = result.summary.overall_metrics
        print(
            f"threshold={result.prediction_threshold:.2f} "
            f"precision={metrics.precision:.4f} "
            f"recall={metrics.recall:.4f} "
            f"f1={metrics.f1_score:.4f} "
            f"fpr={metrics.false_positive_rate:.4f}"
        )


def _print_multi_seed_threshold_sweep(results) -> None:
    print("\nMulti-Seed Threshold Comparison")
    for result in results:
        spread = result.summary.metric_spread
        combined = result.summary.combined_summary.overall_metrics
        print(
            f"threshold={result.prediction_threshold:.2f} "
            f"mean_precision={spread.mean_precision:.4f}+/-{spread.std_precision:.4f} "
            f"mean_recall={spread.mean_recall:.4f}+/-{spread.std_recall:.4f} "
            f"mean_f1={spread.mean_f1_score:.4f}+/-{spread.std_f1_score:.4f} "
            f"mean_fpr={spread.mean_false_positive_rate:.4f}+/-"
            f"{spread.std_false_positive_rate:.4f} "
            f"combined_precision={combined.precision:.4f} "
            f"combined_recall={combined.recall:.4f} "
            f"combined_f1={combined.f1_score:.4f} "
            f"combined_fpr={combined.false_positive_rate:.4f}"
        )


def _print_detector_comparison(summaries) -> None:
    print("\nDetector Comparison")
    print("detector_name,precision,recall,f1,false_positive_rate")
    for detector_name, summary in summaries.items():
        metrics = summary.combined_summary.overall_metrics
        print(
            f"{detector_name},"
            f"{metrics.precision:.4f},"
            f"{metrics.recall:.4f},"
            f"{metrics.f1_score:.4f},"
            f"{metrics.false_positive_rate:.4f}"
        )


def _summary_for_threshold(results, threshold: float):
    for result in results:
        if result.prediction_threshold == threshold:
            return result.summary
    return None


if __name__ == "__main__":
    main()
