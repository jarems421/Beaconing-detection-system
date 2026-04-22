# How To Run Experiments

This project uses a `src/` layout. The cleanest local setup is:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

For lint tooling, install the optional dev dependency:

```powershell
python -m pip install -e ".[dev]"
```

If you do not install the package, set `PYTHONPATH` before running modules:

```powershell
$env:PYTHONPATH='src'
```

## Tests

Run the full test suite:

```powershell
python -m unittest discover -s tests
```

Run lint checks:

```powershell
python -m ruff check .
```

## Main Evaluation Entrypoint

Run a quick sanity evaluation:

```powershell
python -m beacon_detector.evaluation.run --quick
```

Run quick evaluation and write CSV/JSON exports:

```powershell
python -m beacon_detector.evaluation.run --quick --export-results --output-dir results/tables/quick_check
```

Run the default evaluation entrypoint:

```powershell
python -m beacon_detector.evaluation.run
```

## Report-Ready And Final-Story Tables/Figures

Regenerate the report-ready summaries and curated final-story tables/figures from existing exported CSVs:

```powershell
python -c "from beacon_detector.evaluation.report_artifacts import build_report_artifacts; build_report_artifacts()"
```

This writes:

```text
results/tables/report_ready/
results/tables/final_story/
results/figures/
results/figures/final_story/
```

It does not rerun detectors.

## CTU-13 Public Dataset Evaluation

The first public adapter targets CTU-13 bidirectional `.binetflow` files from the
`detailed-bidirectional-flow-labels` folders.

Example using scenario 7:

```powershell
python -m beacon_detector.evaluation.run_ctu13 --input data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario-name ctu13_scenario_7 --output-dir results/tables/ctu13
```

For a parser smoke test on a large file, cap rows explicitly:

```powershell
python -m beacon_detector.evaluation.run_ctu13 --input data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario-name ctu13_scenario_7_sample --output-dir results/tables/ctu13_sample --max-rows 50000
```

Default label mapping:

```text
From-Botnet -> beacon
From-Normal -> benign
Background -> excluded
To-Botnet / To-Normal -> excluded
```

Background and `To-*` labels are excluded by default because CTU-13 documentation describes them as
ambiguous for clean malicious/benign evaluation.

Multi-scenario direct transfer with separate background sensitivity:

```powershell
python -m beacon_detector.evaluation.run_ctu13 --scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --scenario ctu13_scenario_7=data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/tables/ctu13_multi
```

If you only want the primary conservative policy, add:

```powershell
--skip-background-sensitivity
```

The background sensitivity run is much heavier because it includes many ambiguous CTU Background
flows as benign. Treat it as a sensitivity check, not the headline result.

Run the focused CTU feature-distribution diagnostic:

```powershell
python -m beacon_detector.evaluation.run_ctu13_diagnostics
```

This writes distribution, shift-ranking, and protocol/port summaries under:

```text
results/tables/ctu13_feature_diagnostic/
```

Run the CTU-native feature-path comparison:

```powershell
python -m beacon_detector.evaluation.run_ctu13_native --scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --scenario ctu13_scenario_7=data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/tables/ctu13_native
```

This keeps CTU-native fields separate from synthetic `FlowFeatures`. Rule and synthetic-trained RF
are marked as schema-incompatible on the native path; the separate within-CTU supervised command below
trains CTU-native Logistic Regression and Random Forest without blurring the transfer story.


## Within-CTU Supervised Evaluation

Run the final CTU-native supervised stage with leave-one-scenario-out splits:

```powershell
python -m beacon_detector.evaluation.run_ctu13_supervised --scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --scenario ctu13_scenario_7=data/public/ctu13/scenario_7/capture20110816-2.binetflow --scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/tables/ctu13_supervised
```

This is separate from both synthetic direct transfer to CTU and CTU-native unsupervised evaluation.
The conservative label policy is the headline result; Background-as-benign is exported separately as
a sensitivity analysis.

## Lightweight Local Scorer

Score a CTU `.binetflow` file using explicit CTU training scenarios:

```powershell
python -m beacon_detector.cli.score --input data/public/ctu13/scenario_7/capture20110816-2.binetflow --input-format ctu13-binetflow --detector ctu-native-random-forest --train-scenario ctu13_scenario_5=data/public/ctu13/scenario_5/capture20110815-2.binetflow --train-scenario ctu13_scenario_11=data/public/ctu13/scenario_11/capture20110818-2.binetflow --output-dir results/scored/ctu13_scenario_7
```

The scorer writes a scored CSV, summary JSON, and compact markdown summary. It is a local research
interface, not a dashboard or production monitoring system.

## Experiment-Specific Studies

The project has several experiment modules that currently expose Python functions rather than a
single large command-line interface. The examples below are the current direct invocation style.

### Shortcut Stress Suite

```powershell
python -c "from beacon_detector.evaluation import build_shortcut_stress_suite, export_shortcut_stress_tables, run_shortcut_stress_comparison; cases=build_shortcut_stress_suite(); results=run_shortcut_stress_comparison(stress_cases=cases); export_shortcut_stress_tables(output_dir='results/tables/shortcut_stress', results=results, stress_cases=cases)"
```

### Minimum-Evidence Study

```powershell
python -c "from beacon_detector.evaluation import build_minimum_evidence_cases, export_minimum_evidence_tables, run_minimum_evidence_study; cases=build_minimum_evidence_cases(); result=run_minimum_evidence_study(cases=cases); export_minimum_evidence_tables(output_dir='results/tables/minimum_evidence', result=result, cases=cases)"
```

### RF Time+Size Signal Study

```powershell
python -c "from beacon_detector.evaluation import build_time_size_signal_study_cases, export_rf_time_size_signal_study_tables, run_rf_time_size_signal_study; cases=build_time_size_signal_study_cases(); result=run_rf_time_size_signal_study(study_cases=cases); export_rf_time_size_signal_study_tables(output_dir='results/tables/rf_signal_study', result=result, study_cases=cases)"
```

### RF Diagnostics

```powershell
python -c "from beacon_detector.evaluation import build_stress_eval_harder_suite, build_stress_training_suite, export_rf_diagnostic_tables, run_rf_time_size_jittered_diagnostic, run_stress_trained_rf_experiment; train=build_stress_training_suite(); eval_cases=build_stress_eval_harder_suite(); diagnostic=run_rf_time_size_jittered_diagnostic(); stress=run_stress_trained_rf_experiment(stress_training_cases=train, stress_eval_cases=eval_cases); export_rf_diagnostic_tables(output_dir='results/tables/rf_diagnostics', diagnostic=diagnostic, stress_results=stress, stress_training_cases=train, stress_eval_cases=eval_cases)"
```

## Ruff

The repository has minimal Ruff configuration in `pyproject.toml`.

Check code:

```powershell
ruff check src tests
```

Format code:

```powershell
ruff format src tests
```

This project intentionally does not require a large tooling stack. Ruff is included as lightweight
lint/format support only.
