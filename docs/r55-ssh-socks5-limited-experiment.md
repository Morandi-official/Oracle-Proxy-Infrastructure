# R55 — Optional user-mode SOCKS5 proxy over verified Oracle SSH

## This is NOT a WireGuard replacement

R55 is an **additional, completely separate opt-in transport experiment**,
not a production VPN/WFP switch or the original WireSock-replacement
architecture. The assistant must not claim it is native WireGuard.
It uses Windows built-in OpenSSH as the encrypted upstream transport.
It provides a local **application-only SOCKS5 TCP listener** at
`127.0.0.1:10880` after an operator explicitly supplies the SSH host,
username, local existing SSH identity file, and optionally SSH port.
Nothing is enabled at startup with no arguments.

It may offer an actual browser proxy through an Oracle host **if** that
Oracle server supports OpenSSH login and TCP forwarding and has been
independently verified. GitHub runner tests do not possess Oracle keys
and do **not** claim an Oracle handshake or real browsing exit-IP proof.

## Essential security boundaries

- The optional R55 binary contains no WireGuardNT, VPN drivers, Windows
  SCM service, WFP rules, installer, background auto-start or global
  proxy/DNS/route changes. It cannot affect the UU remote-control stack
  except through indirect effects of user-chosen system/browser settings.
- Hostnames and usernames are strict ASCII fields, passed as distinct
  `ProcessStartInfo.ArgumentList` values, never interpolated into a
  shell command. Hostnames cannot begin with `-` or contain `@`, spaces,
  shell metacharacters, or custom SSH option syntax.
- It executes only `%SystemRoot%\System32\OpenSSH\ssh.exe` with
  `-F none`, `BatchMode=yes`, `StrictHostKeyChecking=yes`,
  `IdentitiesOnly=yes`, `ExitOnForwardFailure=yes`,
  `GatewayPorts=no` and fixed `-D 127.0.0.1:10880`.
  It does **not** automatically accept the first unknown server host
  key; never use `StrictHostKeyChecking=no`.
- The private key is read by OpenSSH on the local PC. The app never
  saves or uploads the key, and GitHub build contains no credential.
  No SSH client `-o` or shell arguments are taken directly from
  user text.
- The SSH process is assigned to a Windows Job Object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Normal Enter / Ctrl+C and
  helper exit close the job and stop the child. If the job cannot be
  established or assigned, the connection fails rather than leaking
  an unmanaged process.
- The local listening port is checked before startup, and the program
  checks an actual localhost TCP socket before announcing readiness.
  **Local listener readiness is NOT evidence the remote Oracle egress
  works**. Firefox or a similar per-app browser must independently
  verify the intended destination IP from its own SOCKS connection.

## Requirements and optional user trial

1. Keep WireSock, UU and your existing working networking unchanged.
2. Have your **own**, already configured Oracle SSH login and private
   key. Confirm Oracle's SSH server fingerprint against an independent
   trustworthy source, and explicitly add that verified host identity
   to your local Windows OpenSSH `known_hosts` before using R55.
   Never paste a private key into a chat.
3. Only if Windows security permits this *unsigned* test executable,
   open regular user PowerShell in the extracted folder and run
   `& '.\OracleProxy.AppSocks5.Experimental.exe' --help`.
   Do not bypass SmartScreen or change `ExecutionPolicy`.
4. An example syntax (fill with *your own* values locally, not here):
   `& '.\OracleProxy.AppSocks5.Experimental.exe' --host '<YOUR_OCI_SSH_HOST>' --user opc --identity 'C:\Users\<YOU>\.ssh\id_ed25519' --ssh-port 22`.
   This must NOT be started until the host key is explicitly trusted.
5. A successful process prints `R55_LOCAL_SOCKS5_LISTENING`.
   In **a separately configured browser that has its own proxy UI**
   (for example Firefox), choose SOCKS5 host `127.0.0.1`, port
   `10880`, and enable "Proxy DNS when using SOCKS v5". Test a website
   and verify the externally observed exit IP. Do not turn on global
   Windows proxy configuration or send UU/game traffic through SOCKS.
6. Return to the local console and press Enter to terminate R55, then
   remove the browser's per-app SOCKS setting. The program does not
   retain state after closing.

The Windows runner CI tests the CLI parser and rejects SSH option
injection, ensures an actual Windows OpenSSH binary exists, checks the
default no-args mode does not listen, verifies no VPN/filter components
ship, and uploads a separate portable unsigned ZIP. It does NOT have
the user's Oracle credentials, cannot verify `AllowTcpForwarding`,
real Oracle tunnel throughput, split DNS, malicious local processes
on the same PC, or credential integrity beyond OpenSSH's established
mechanisms. Those require supervised acceptance.

**Do not confuse this interim SSH experiment with safe native VPN
readiness.** Full-device IPv4/IPv6 kill switch, authenticated SYSTEM
control, production WireGuard client, UU continuity under WFP and GA
issue #34 remain separate and OPEN.
