# Local administrator login and official transfer balance

The owner requested a fixed administrator username/password without GitHub login or MFA. `oracle-ops` supplies `ORACLE_ADMIN_LOCAL_USERNAME` and `ORACLE_ADMIN_LOCAL_PASSWORD` (12–128 characters). The existing fixed root configure operation hashes the password using salted PBKDF2-SHA256 before writing the root-only environment. Deployment provisions only that exact Django staff user; it does not grant Django superuser rights, expose registration, or permit VPN client credentials to administer the server. Local mode closes all `/accounts/` routes and uses CSRF-protected password login and POST logout, secure session cookies, one-hour assurance and persistent rate limits. Previous GitHub accounts and encrypted MFA data remain dormant for attended rollback. The production browser acceptance checks actual password login, read-only control access and logout in Chromium and Firefox without exporting credentials or browser state.

## Official free-transfer calculation

On 2026-10-23, Oracle public pricing confirmed SKU B88327 (North America, Europe and UK), B93455 (APAC, Japan and South America) and B93456 (Middle East and Africa) use **Gigabyte Outbound Data Transfer Per Month**. Their USD PAY_AS_YOU_GO zero-price tier has `rangeMin=0`, `rangeMax=10240`; the next tier is paid. Sources:

- https://www.oracle.com/cloud/networking/pricing/
- https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=USD
- Read-only reference run: https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39976279652

The existing instance-principal Usage API query now groups by exact SKU part number and follows bounded pagination. For a complete set of recognized rows in one transfer zone, the dashboard shows **10,240 API GB minus official reported usage**, retaining the original API GB unit even when the billing label is `GB Months`. This is derived from official usage and the official zero-price tier; it is not an Oracle live remaining-balance endpoint. The UTC billing cutoff and observation age remain visible, and current uncompleted-day traffic is not silently included. VNIC byte counters and the existing local enforcement budget remain separate.

Empty results, incomplete pagination, unknown SKUs/units, multiple pricing zones and stale data never become a full free balance. No new IAM grants or paid services are required. The Oracle download mirror in PR203 remains paused and is excluded from this deployment.
