# R66 — Live default GUI -> protected LocalSystem SCM fail-closed control

Date: 2026-10-17, PR #96, disposable Windows CI:
https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38993853957

The normal R5 disposable installer builds the **default**, lab-control
excluded manager and read-only GUI, verifies protected staging ACLs,
installs a demand-only LocalSystem SCM service and authenticates the
GUI's read-only STATUS IPC against the real service PID and Session 0.

R66 also invokes the existing real GUI
`--manager-control-denial-test` **while the installed default service
is running**, thereby verifying that both fixed-profile
`RequestConnect` and `RequestExplicitDisconnect` are answered with
the expected refusal from the actual SYSTEM named pipe server. The GUI
must OS-bind the pipe server PID to the expected SCM service; the SYSTEM
manager derives caller authorization through impersonated Windows token,
not a JSON role.

Observed job markers:

- `R66_DEFAULT_GUI_TO_REAL_SYSTEM_CONTROL_DENIAL_PASS`
- `R5_INSTALL_SMOKE_PASS`
- `R5_UNINSTALL_SMOKE_PASS`
- `R20_AFTERSTAGE_ROLLBACK_PASS`
- `R20_AFTERSCMCREATE_ROLLBACK_PASS`
- `R20_AFTERSCMSTART_ROLLBACK_PASS`
- `R20_PREEXISTING_DATA_PRESERVED_PASS`
- `R20_INSTALLER_FAILURE_RECOVERY_PASS`

After tests, only the exact CI-owned service and staging directory were
removed; runner route, DNS and firewall inventory did not change.

Important: this is a proof of **authenticated refusal**, not authenticated
production tunnel activation. It is a *status-only*, disposable, unsigned
installer and cannot be promoted to a signed/production WireSock replacement.
The legitimate production backend remains unavailable until real WFP and
remote-control safety conditions are met. GA Issue #34 remains open.
