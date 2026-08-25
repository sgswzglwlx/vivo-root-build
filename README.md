# PD2415 6.6.89 Full-Flow Candidate

This source is based on the same-device/same-SoC PD2415 6.6.57 IonStack engine:
perf KASLR, pselect GhostLock, CFI fops, pipe physrw. The dumpstate carrier
closure is retained from the validated PD2241 method.

The archived 6.6.89 target keeps `TARGET_DESTRUCTIVE_WRITE_ENABLED=0`. The
retained full-flow build therefore stops in `target_preflight()` before exploit
setup while physical-map, linked-base, `vr.ko`, and carrier preimage facts
remain unproved. The read-only inspection path is still available for geometry
and environment checks.

Build on Windows:

    powershell -ExecutionPolicy Bypass -File .\\build.ps1
