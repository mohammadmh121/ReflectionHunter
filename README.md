# ReflectionHunter

**Auditing and Detecting Windows Process Cloning via `ntdll!RtlCreateProcessReflection`**

This repository contains the proof-of-concept telemetry simulator, Sysmon configuration, Splunk SPL hunting query, and Sigma correlation rule accompanying my research on Windows process reflection.

* **Full Technical Write-up (Portfolio):** [Read on mohammadmh121.github.io](https://mohammadmh121.github.io/reflection-hunter/)
* **Full Technical Write-up (Medium):** [Read on Medium](#) *(Replace `#` with your Medium URL)*

---

## Research Overview

* **Two-Stage Cross-Process Architecture:** `ntdll!RtlCloneUserProcess` can only clone the calling process (`NtCurrentProcess`). To clone a remote process, `RtlCreateProcessReflection` maps a shared memory section (`ZwCreateSection` / `ZwMapViewOfSection`) and injects an unexported worker thread (`ntdll!RtlpProcessReflectionStartup`) into the target process.
* **Minimum Handle Access Mask (`0x044A` -> `0x144A`):** Cross-process reflection requires `PROCESS_CREATE_THREAD (0x0002) | PROCESS_VM_OPERATION (0x0008) | PROCESS_DUP_HANDLE (0x0040) | PROCESS_QUERY_INFORMATION (0x0400) = 0x044A`. Windows automatically grants `PROCESS_QUERY_LIMITED_INFORMATION (0x1000)` alongside `0x0400`, logging `0x144A` in Sysmon Event ID 10.
* **Implicit PPID Distortion:** Because `NtCreateUserProcess` is invoked from inside the injected thread in the target process, kernel creation callbacks (`PspInsertThread`) record the target process as the parent of the newly cloned process in Sysmon Event ID 1, hiding the true initiator.
* **Telemetry Correlation:** Correlating Sysmon Event ID 10 (bitwise check for the `0x004A` + query bits) with Sysmon Event ID 8 (`StartModule` ending in `\ntdll.dll` with an unexported `-` `StartFunction`) reliably detects cross-process reflection within a 5-second window.

---

## Repository Structure

```text
ReflectionHunter/
├── src/
│   └── ReflectionTelemetrySim.cpp        # Shellcode-free x64 PoC simulator
├── detections/
│   ├── sigma/
│   │   └── reflection_correlation.yml    # Temporal correlation Sigma rule
│   └── splunk/
│       └── reflection_hunting.spl        # Normalized bitwise Splunk SPL query
└── configs/
    └── sysmon-config.xml                 # Lab Sysmon v15.15 configuration
