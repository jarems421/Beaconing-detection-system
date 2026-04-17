# Experiment Log

This log records major project milestones and findings. It is intentionally concise: the detailed metrics live in `results/tables/`.

## Phase 1: Project Structure And Core Models

Change: Created a `src/beacon_detector/` package with data, flow, feature, detection, and evaluation modules.

Main result: The project has reusable models for traffic events, flow keys, flows, and flow feature records.

Conclusion: The pipeline is organized around flow-level detection rather than packet-level signatures.

## Phase 2: Synthetic Data Generation

Change: Added labelled synthetic traffic generation for normal traffic, fixed periodic beaconing, jittered beaconing, bursty beaconing, and time+size jittered beaconing.

Main result: Synthetic events can be written to CSV under `data/synthetic/` and loaded back for flow construction.

Conclusion: Synthetic data gives a controlled benchmark, but it must be treated as synthetic evidence rather than real-world proof.

## Phase 3: Flow Construction And Feature Extraction

Change: Added flow grouping by `src_ip`, `dst_ip`, `dst_port`, and `protocol`, plus flow-level behavioural feature extraction.

Main result: Features now cover timing, rate, burst shape, size variation, cadence consistency, and structural size descriptors.

Conclusion: Feature engineering is the center of the project because every detector uses the same flow-level feature rows.

## Phase 4: Rule Baseline Hardening

Change: Implemented and tuned an interpretable rule-based detector, then froze it as the baseline configuration.

Main result: The rule baseline is strong and explainable on obvious beaconing, but brittle under evasive jitter and benign repeated traffic.

Conclusion: The rule detector is useful as an interpretable baseline, not as the final detector.

## Phase 5: Hard Benign Profiles

Change: Added explicit benign profile labels such as `normal_telemetry`, `normal_keepalive`, `normal_api_polling`, and `normal_bursty_session`.

Main result: Benign repeated traffic exposed false positives that were hidden when normal traffic was too generic.

Conclusion: Keeping benign traffic subclassed is essential for credible diagnosis.

## Phase 6: Statistical Baseline

Change: Added a transparent statistical baseline using benign reference behaviour and z-score style distance.

Main result: The statistical baseline is easy to explain, but it struggles with multimodal benign traffic.

Conclusion: It is a useful bridge between rules and ML, but not strong enough as the main detector.

## Phase 7: Anomaly Baselines

Change: Added Isolation Forest and Local Outlier Factor using the same flow-level features.

Main result: LOF is a meaningful anomaly baseline, while Isolation Forest was weaker in the current benchmark.

Conclusion: Anomaly detection is useful for comparison, but it did not outperform supervised RF.

## Phase 8: Supervised ML

Change: Added Logistic Regression and Random Forest supervised baselines.

Main result: Random Forest became the strongest overall detector on the standard hardened synthetic benchmark.

Conclusion: Supervised ML is powerful on the current synthetic setup, but shortcut learning remains a concern.

## Phase 9: Held-Out Validation And Feature Ablation

Change: Added held-out scenario, parameter-regime, and benign-profile validation, plus supervised feature ablations.

Main result: RF performs well overall but weakens on low-event and withheld `time_size_jittered` regimes.

Conclusion: RF is not simply learning robust beaconing behaviour in all cases; event count and size features remain important.

## Phase 10: Shortcut / Overlap Stress Testing

Change: Added explicit overlap controls for event count, size variation, duration-like timing, and hard `time_size_jittered` variants.

Main result: RF still performed well overall, but completely missed the hardest low-event high-jitter size-overlapping `time_size_jittered` flows.

Conclusion: The hardest evasive regime is a real weakness, not just a reporting artifact.

## Phase 11: Feature Improvement And RF Diagnostics

Change: Added targeted behavioural features and diagnostic exports for missed `time_size_jittered` flows.

Main result: New features improved some aggregate RF results and reduced false positives, but did not solve the hardest `time_size_jittered` failures.

Conclusion: The missed hard flows are confidently classified as benign, not merely near the threshold.

## Phase 12: Signal Study

Change: Added a one-factor-at-a-time study for hard `time_size_jittered`, varying event count, timing jitter, size jitter, duration, and benign overlap.

Main result: Event count was the dominant factor. At 5-9 events, RF confidence collapsed even when other factors were made easier.

Conclusion: The project is observing a minimum-evidence problem, not only a threshold problem.

## Phase 13: Minimum-Evidence Analysis

Change: Added a controlled event-count sweep for fixed, jittered, bursty, time+size jittered, and hard-overlap time+size jittered scenarios.

Main result: RF detects easy regimes with about 3 events, while evasive `time_size_jittered` needs about 12 events for RF @ 0.3 to become reliable. RF @ 0.6 needs more evidence.

Conclusion: The amount of flow history available is a core determinant of detection reliability.
