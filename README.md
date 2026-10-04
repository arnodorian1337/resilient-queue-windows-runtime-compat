# Resilient Queue Worker

Small reference worker used to test retry and compatibility behavior on
Windows. Release and validation notes are kept in Git history so the working
tree stays small.

`src/worker.py` is the example worker. `tools/compatcheck.exe` is the
self-contained Windows compatibility check used by older build agents. Its
source is kept under `tools/source/`.

