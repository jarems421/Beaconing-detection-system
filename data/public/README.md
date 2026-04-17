# Public Dataset Files

This project includes a CTU-13 adapter, but raw CTU-13 `.binetflow` files are not committed to the
repository because they are external public dataset artifacts and can be large.

Expected local layout for CTU-13 experiments:

```text
data/public/ctu13/
  scenario_5/capture20110815-2.binetflow
  scenario_7/capture20110816-2.binetflow
  scenario_11/capture20110818-2.binetflow
```

See `docs/how_to_run_experiments.md` for the CTU direct-transfer, CTU-native, supervised, and CLI
commands.
