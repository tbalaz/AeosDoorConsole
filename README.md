# AEOS Door Console

A small local web page that talks to a Nedap AEOS SOAP web service: list the doors (entrances) and lock, unlock or
provide access per door. It is one PowerShell script, no install, no internet needed.

The script is generic. Nedap's web service document is not public, so no AEOS operation name is built in: you map
each action to a WSDL operation and a request template on site (Setup tab). Everything it sends is also written to a
debug log, so when something does not work you can send that log back.

## Requirements

- Windows with Windows PowerShell 5.1 (built in). Not PowerShell 7.
- This PC can reach the AEOS server web service (typically `https://<aeos-server>:8443/aeosws`).
- An AEOS user that is allowed to use the web service.
- No administrator rights needed.

## Run

```
powershell -ExecutionPolicy Bypass -File .\Aeos-DoorConsole.ps1
```

Options: `-Port 8765` (default), `-ConfigFile <path>` (default `aeos-console.json` next to the script, created on first
run), `-NoBrowser` (do not open the browser). The page opens on `http://localhost:8765/`. Press Ctrl+C in the window
to stop. Only this PC can reach the page.

Files created next to the script: `aeos-console.json` (your settings), `aeos-console-audit.jsonl` (audit),
`aeos-console-debug.log` (debug log), `aeos-console-diag-<time>.zip` (diagnostics, on request).

## First-run setup on site

1. **Start** the script, open the page, and open the **Setup** tab.
2. **Connection.** Enter the AEOS URL (for example `https://aeos-server.example.local:8443/aeosws`). Leave the WSDL URL
   empty to use the AEOS URL plus `?wsdl`, or paste the WSDL URL if you were given one.
3. **Log in** at the top of the page with the AEOS user and password. The password is kept in memory only: it is never
   written to disk, never put in the log, and is forgotten when you log out or stop the script.
4. **Load WSDL.** Click *Load WSDL*. It saves what is on the Setup tab first, so a URL you just typed is used, then
   fills every operation dropdown with the operations of the service, sorted A-Z. If your AEOS version publishes no
   WSDL, get the WSDL file or the web service document from the AEOS administrator.
5. **Map each action.** For each of *List doors*, *Lock*, *Unlock*, *Provide access*:
   - pick the WSDL operation in the dropdown (the SOAP action is filled in for you);
   - click *Insert skeleton* to get an empty request for that operation, then fill in the parameters;
   - put the door id where the operation expects it with the placeholder `{{id}}`.
   Leave an action unmapped to hide its button.
6. **Template placeholders.** The body is the XML that goes inside the SOAP Body. These are replaced before sending:

   | Placeholder | Replaced by |
   |---|---|
   | `{{id}}` | the door id (XML-escaped) |
   | `{{name}}` | the door name (XML-escaped) |
   | `{{ns}}` | the namespace prefix from Setup (default `aeos`) |
   | `{{tns}}` | the target namespace (filled from the WSDL) |

   Example: `<aeos:SomeOperation><aeos:entranceId>{{id}}</aeos:entranceId></aeos:SomeOperation>`.
   A body that is not well-formed XML is refused before anything is sent.
7. **Door list parsing.** For *List doors* set *Door element* (the XML element that repeats once per door), *Id field*
   and *Name field* (element names inside it) and optional *Extra columns*. Matching is by element name only, ignoring
   namespaces and prefixes. Use *Raw call* or *Test list* to look at a real response first if you do not know the names.
8. **Authentication.** *HTTP Basic* (default) sends the user and password in the HTTP header. *WS-Security
   UsernameToken* puts them in the SOAP header (PasswordText). Try Basic first; if AEOS answers 401 or a security fault,
   try the other.
9. **SOAP version.** 1.1 or 1.2. *Load WSDL* sets it from the WSDL. Change it only if the server rejects the content type.
10. **TLS.** Certificates are checked. If the AEOS server uses a self-signed or internal-CA certificate that this PC does
    not trust, either install the CA on this PC (preferred) or tick *Skip TLS certificate validation*. A red warning
    banner stays on the page while it is on. The skip applies to AEOS calls only. The log records the server certificate
    (subject, issuer, thumbprint, validity, names) on every connection.
11. **Save** (the Save bar stays at the bottom of the window while you scroll the Setup tab), then *Test list* (it uses
    the saved settings): it shows how many doors were parsed and the raw response.
12. Go to **Doors**, *Load doors*, and use the buttons. Actions ask for confirmation in the page.

## Finding the right operations: Aeos-WsdlHelper.ps1

AEOS publishes some 200 operations, named verb first (`change...`, `find...`), so the door ones are hard to spot in
the dropdowns. `Aeos-WsdlHelper.ps1` (read-only, sends no SOAP request) lists the operations whose names match a
pattern, each with its request element, its fields and the allowed values of fields with a fixed value list (such as
a mode or state):

```
powershell -ExecutionPolicy Bypass -File .\Aeos-WsdlHelper.ps1 -AeosUrl https://<aeos-server>:8443/aeosws -SkipTlsCheck
```

The default pattern looks for access points, entrances, doors, lock, release, block, open, mode, state and status;
`-Match entrance` narrows it, `-Match .` lists everything. `-FieldMatch 'lock|unlock'` instead finds operations by
their request fields and allowed values, whatever the operation is called (add `-Match` to combine both). Add
`-AskCredential` if the WSDL needs the AEOS login.
The output is also saved as `aeos-wsdl-<time>.txt` next to the script - send that file back when asking for help.

## Door commands over the socket interface: Aeos-SocketTest.ps1

AEOS's SOAP service lists the doors (`findAccessPoint` returns each access point's `Name` and `HostName`) but has no
lock or unlock operation. Door commands go through the AEOS socket interface (TCP 8035), which the Milestone Nedap
plugin also uses; the AEOS log shows them as `execute(<function>,"<HostName>:<Name>");` with the functions `lock`,
`unlock`, `normal` (access control activated), `provideAccess`, `isLocked` and `isUnlocked`.

`Aeos-SocketTest.ps1` connects once, logs in, sends `setRmiCommandConnection(true);` and ONE function, and prints
every byte AEOS sends back (control characters shown as `<CR>` `<LF>` `<ETX>`), saved as `aeos-socket-<time>.txt`:

```
powershell -ExecutionPolicy Bypass -File .\Aeos-SocketTest.ps1 -AeosHost <aeos-server> -AccessPoint "<HostName>:<Name>"
```

The default function `isLocked` only asks for the state. `-Function lock|unlock|normal|provideAccess` changes the
door and asks for YES first. `-UseExecuteArgs` sends `executeArgs(<function>,[],"<HostName>:<Name>");` instead,
`-Terminator LF|None` changes what follows each `;` (default CR LF). The password is never printed or saved, but the
socket interface is plain TCP, so it crosses the network unencrypted (as for every socket client).

## Tabs

- **Doors**: load, filter, and run the mapped actions. Each row shows the result and a **request id**.
- **Setup**: connection and mappings (above).
- **Raw call**: send any request body to the service and see the response. Use this to explore the web service.
- **Audit**: the last 50 door actions and whether the audit chain is intact.
- **Debug**: live view of the debug log, download of the whole log, diagnostics zip.

## Debug log and diagnostics (please send these back)

When something fails, **send the debug log or the diagnostics zip to the integrator**. They are written for this.

- **Debug log**: `aeos-console-debug.log` next to the script (setting *Debug log file* changes the place; it rotates at
  10 MB to `.1`). It is always on. It holds the start-up details (script, PowerShell, .NET, OS, enabled TLS versions,
  settings), every request to AEOS with headers and the full SOAP request and response, the server certificate details,
  every error with all inner exceptions and stack trace, and every call the page makes to this script. The setting
  *Debug level* `basic` leaves the SOAP bodies out.
- **Where the log lines are**: every error on the page ends with `(request id xxxxxxxx)`. That id starts the matching
  lines in the log. Please include the id when you report a problem.
- **Diagnostics zip**: Debug tab, *Create diagnostics zip*. It shows the path of `aeos-console-diag-<time>.zip` and a
  download link. It contains the debug log, your settings, the audit file and a short environment report.
- **Secrets**: the password is never written. The `Authorization` header is logged as `Basic ****`, a WS-Security
  password as `****`, and the password text itself is replaced by `****` anywhere before a line is written. The log does
  contain the user name, machine name, door names and AEOS responses, so treat it as confidential company data.

## Audit

Every door action (success or failure) is appended to `aeos-console-audit.jsonl` before the page gets its answer: time (UTC),
Windows user, AEOS user, action, door, HTTP status, result and fault text. Each record carries the hash of the previous one
(SHA-256 chain), so a changed or deleted line breaks the chain; the Audit tab shows "Chain OK" or "CHAIN BROKEN".

## Security notes

- The page listens on `localhost` only. Every call from the page carries a random per-start token and the `Origin` is
  checked, so another web page in your browser cannot trigger a door action through this port.
- No data is sent anywhere except to the AEOS URL you configured. No CDN, no telemetry.
- Use HTTPS to the AEOS server. With plain `http://` the password travels unencrypted (the page warns).
- Certificate validation is on unless you switch it off per the TLS step above.
- The debug log and diagnostics contain no password but do contain operational details; do not post them publicly.
- Stop the script (Ctrl+C) when you are done.

