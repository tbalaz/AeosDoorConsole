# DoorKeeper

DoorKeeper by IT42 is a small local web page for Nedap AEOS. It talks to an AEOS server: list the doors (entrances) over the SOAP web service and
lock, unlock, provide access or set a door back to normal per door, over SOAP or over the AEOS socket interface. It is
one PowerShell script, no install, no internet needed.

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
powershell -ExecutionPolicy Bypass -File .\DoorKeeper.ps1
```

Options: `-Port 8765` (default), `-ConfigFile <path>` (default `doorkeeper.json` next to the script, created on first
run; an existing `aeos-console.json` from an older version is used when `doorkeeper.json` is missing), `-NoBrowser` (do not open the browser). The page opens on `http://localhost:8765/`. Press Ctrl+C in the window
to stop. Only this PC can reach the page.

Files created next to the script: `doorkeeper.json` (your settings), `doorkeeper-audit.jsonl` (audit),
`doorkeeper-debug.log` (debug log), `doorkeeper-diag-<time>.zip` (diagnostics, on request).

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
   | `{{start}}` | List doors only: the record offset of the page (0, page size, 2 x page size, ...) |
   | `{{pageSize}}` | List doors only: the *Page size* |

   Example: `<aeos:SomeOperation><aeos:entranceId>{{id}}</aeos:entranceId></aeos:SomeOperation>`.
   A body that is not well-formed XML is refused before anything is sent.
7. **Door list parsing.** For *List doors* set *Door element* (the XML element that repeats once per door), *Id field*
   and *Name field* (element names inside it) and optional *Extra columns*. Matching is by element name only, ignoring
   namespaces and prefixes. Use *Raw call* or *Test list* to look at a real response first if you do not know the names.
   **Paging.** A server that returns only a limited number of doors per call (AEOS: 500) is read page by page: set
   *Page size* to that number and put `{{start}}` (and `{{pageSize}}`) where the request takes the offset and the count.
   DoorKeeper then asks page after page until a page comes back short; *Test list* says how many pages it read. A door
   that comes back twice is listed once; a failed page fails the whole list. *Page size* 0 = one request.
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

## Door actions over the socket interface (Setup tab)

AEOS 2023.2 has no door command in its SOAP service, so lock / unlock / access / normal go over the AEOS socket
interface (TCP, TLS 1.2). Each of the four actions has a **Transport** (SOAP or Socket); *List doors* stays SOAP.
Nothing AEOS-specific is built in: you type the values below on the Setup tab, **Socket interface** section and per
action. The console opens one connection per click: connect, read the greeting, send the login, send each init
command, send the action command, read one reply line for each, close. Every line sent and received goes to the debug
log under the request id with control characters shown (`<CR>` `<LF>`); the login line is logged as `login(user,****);`.

| Setup field | Value for AEOS 2023.2 |
|---|---|
| Host | the AEOS server (empty = the host of the AEOS URL) |
| Port | `8035` |
| Use TLS | on |
| Skip TLS certificate validation | on (AEOS ships a Nedap example certificate; a red banner stays on the page) |
| Line terminator | `CRLF` |
| Greeting wait (ms) | `2000` |
| Login command | `login({{user}},{{password}});` (user and password are the ones typed at the top of the page) |
| Login success pattern | `^Response:true;` |
| Init commands | `setRmiCommandConnection(true);` |
| Reply timeout (s) | `10` |
| Lock: Transport / Socket command | Socket / `execute(lock,"{{HostName}}:{{name}}");` (tested on site 2026-11-12) |
| Unlock: Transport / Socket command | Socket / `execute(unlock,"{{HostName}}:{{name}}");` (tested on site 2026-11-12) |
| Provide access: Transport / Socket command | Socket / `execute(provideAccess,"{{HostName}}:{{name}}");` (seen in the AEOS audit log) |
| Normal: Transport / Socket command | Socket / `execute(normal,"{{HostName}}:{{name}}");` (door back to access control activated; seen in the AEOS audit log) |
| Success pattern (each action) | `^Response:` |
| List doors | SOAP: operation `findAccessPoint`, Door element `AccessPoint`, Id field `Id`, Name field `Name`, Extra columns `HostName`, Page size `500` (first page tested on site 2026-11-13; paging not yet tested on site) |
| List doors: request body | `<s:AccessPointSearchInfo xmlns:s="http://www.nedap.com/aeosws/schema"><s:AccessPointInfo/><s:SearchRange><s:startRecordNo>{{start}}</s:startRecordNo><s:nrOfRecords>{{pageSize}}</s:nrOfRecords></s:SearchRange></s:AccessPointSearchInfo>` |

The AEOS request elements live in the schema namespace `http://www.nedap.com/aeosws/schema`, not in the WSDL target
namespace, so the body declares it itself (a body in `{{ns}}` gets "Message part ... was not recognized").

Ready-made settings with all the values above, the door list request and the two door state checks:
`examples/aeos-2023.2/doorkeeper.json`. Stop DoorKeeper (Ctrl+C), copy that file next to `DoorKeeper.ps1` (it replaces
the settings there), start DoorKeeper, type the AEOS URL on the Setup tab, Save, then *Test list*.

Command placeholders: `{{id}}`, `{{name}}` and `{{<extra column>}}` (any extra column of the door list, for example
`{{HostName}}`); `{{user}}` and `{{password}}` work in the login command only. Values are not escaped: a door value
holding a line break, a double quote or a semicolon (and a user name or password also a comma or a closing
parenthesis) is refused with a clear message before anything is sent. A placeholder outside double quotes in the
command also refuses a value with a comma or a parenthesis, so put door placeholders in quotes as in the example
above. The user name and password still refuse only a comma and a closing parenthesis (an opening
parenthesis is fine in a password). A reply counts as success when it matches the
action's *Success pattern* (empty = any reply line); with a *Login success pattern* a rejected login stops the action
with `login rejected: <reply>`. An action with no command stays hidden (the *Normal* button only shows once mapped).
The **Raw call** tab has a *Send socket command* box that runs the same session with one typed command and shows every
line sent and received; it is written to the audit file like a door action.

## Door state, selection and lockdown (Doors tab)

**State column.** On the Setup tab, **Door state** section, you type up to four *checks*. Each check has a label, a
socket command and a match pattern (a regex on the reply line). A door's state is the label of the FIRST check whose
reply matches; when none matches the state is the *Label when no check matches*. A check that got no reply, or a
door with a refused value, shows `?` and the reason in the tooltip (hover the cell). With no check typed there is no
State column. The checks use the Socket interface settings and the same placeholders as the action commands. Nothing
AEOS-specific is built in. State is read after *Load doors*, with the *Refresh state* button (it reads every door
in the list on all pages, so a filter narrows it), and after a door action (same session). One refresh uses ONE socket
session per *Doors per socket session* doors: login and init once, then the checks for every door. No timer: refresh
by hand.

| Setup field (Door state) | Value for AEOS 2023.2 |
|---|---|
| Check 1: label / command / match | `Locked` / `execute(isLocked,"{{HostName}}:{{name}}");` / `^Response:true;$` |
| Check 2: label / command / match | `Unlocked` / `execute(isUnlocked,"{{HostName}}:{{name}}");` / `^Response:true;$` |
| Label when no check matches | `Normal` |
| Doors per socket session | `500` (more doors are read or sent in several sessions, one after the other) |

UNVERIFIED on site: `isLocked` answered `Response:false;` on a real AEOS 2023.2; the `Response:true;` reply and the
`isUnlocked` query have not been tried yet. Try them with the **Raw call** tab socket box on a locked and an unlocked
door first, and adjust the match patterns to what AEOS really answers.

**Pages.** The table shows *Rows per page* doors (25, 50, 100, 250, 500 or All; default 100, remembered by the
browser) with First / Previous / Next / Last above and below it and "Doors 1-100 of 1893, page 1 of 19". The pages
cover the doors the filter box and the location tree leave; a new filter, tree node or door list starts at page 1.

**Selection and batch.** Every door row has a checkbox; the header checkbox selects the doors on
the page. With the whole page ticked, the pager offers *Select all N in the list* (and then *Clear selection*). The batch bar
shows the count and one button per mapped action ("Lock selected" ...); each asks for confirmation naming the number
of doors and the first five names. Over the socket the whole batch is ONE session: login and init once, one command
per door, then the state checks of every door. A door with a refused value (see above) is reported "refused, not
sent" and the others go on. A SOAP action runs call by call. The page waits for the whole batch (the console handles
one request at a time), then fills each row with its result and state. Every door gets its own audit record, tagged
`batch:<request id>`. More doors than *Doors per socket session* go in several sessions, one after the other.

**Lockdown** locks every door in the list (not only the shown or selected ones) with the Lock action. Its confirm
dialog names the action, the number of doors and the first five names. It shows only when Lock is mapped.

## Locations, door groups and Arm / Disarm (Doors tab)

Controller or door names often hold the place of the door. DoorKeeper reads it from the names, shows the doors as a
tree and arms a whole building, floor or city in one step. All of it is off until you type the *levels* on the Setup tab.
The examples use a MADE-UP scheme, `BE-BRU-HQ1-B1-F00` = country-city-site-building-floor; your site has its own.

**Setup tab, Locations.**
- *Levels*: the level names in order, comma separated (`country, city, site, building, floor`). Plain names, no spaces.
- *Rules*, one per line: `<source> <pattern>`. The source is `name`, `id` or an extra column of the door list (for
  example `HostName`). The pattern is a regular expression with NAMED groups, for example
  `HostName ^(?<country>[A-Z]{2})-(?<city>[A-Z]{3})-(?<site>[A-Z0-9]+)-(?<building>B\d+)-(?<floor>F\d+)$`. Rules are tried in
  order and the first one that matches wins; each named group becomes a field of the door.
- *Map*, one line per name that does not follow the scheme: `key;value level 1;value level 2;...` (the columns follow
  the levels; the key is a door id, a door name or a value of an extra column such as the controller name). The map
  overrides the rules. *Import the map from a CSV file* fills the box from a file (a first line starting with `key` is
  skipped). The Setup page keeps only the level columns of a map line.
- *Labels*, one per line: `BRU=Brussels`. The tree shows the label, the columns and the reports keep the value.
- *Tester*: type a controller or door name and see which rules match, which fields they give and where the door lands;
  below it, how many of the listed doors each rule places and how many stay unplaced. It works on what is on the page
  now, before Save.
A door whose first level is empty is shown under `(unplaced)`. A door that has the first levels only (for example
country and city) is placed on those nodes and goes no deeper.

**Doors tab.** A tree of the levels sits beside the list. Each node shows its door count and a state summary
(`9 doors - 7 Locked, 2 Normal`). Click a node name to show only its doors (*Show all doors* clears it); tick a node to
select all its doors; tick several nodes on any levels (two floors, a floor in another city). The list gets one column per
level, and the filter box also finds a location value or label. **Arm** and **Disarm** are on every tree node, on every
group and on the batch bar (`Arm selected`). Arm runs the door action in `arming.armAction` (default `lock`), Disarm the
one in `arming.disarmAction` (default `normal`); labels `arming.armLabel` / `arming.disarmLabel`. The confirm names the
place and the number of doors. If that action is not mapped the button is switched off and its tooltip says so; with the
license switched off it is switched off like every other door action. Arm and Disarm use the normal batch: one socket
session, one audit record per door, the state read afterwards, more doors than *Doors per socket session* split into several sessions.

**Door groups** (Setup tab, *Door groups*; `groups` in the config): a name, a location filter such as
`city=BRU,ZAG; building=B1` (a door must match EVERY listed level, any one of a level's values) and / or a list of door
ids. A door that matches the filter or is in the list belongs to the group, so a new door on that floor joins by itself.
The editor shows how many listed doors each group matches. On the Doors tab a group has *Select* (selects only its
doors), *Arm* and *Disarm*.

**Arming report.** After every Arm or Disarm a panel shows what was requested, how many went OK, how many failed
(door, location, reply or fault, state after) and the state of every door afterwards. *Retry failed* runs the action
again on the failed doors only; *Export CSV* downloads the report, which is also kept next to the audit file as
`doorkeeper-arming-<stamp>.csv` with the columns `time, action, group_or_selection, door_id, door_name, location, ok,
reply_or_fault, state_after` (a cell that starts with `=`, `+`, `-` or `@` gets a `'` in front).

Config keys (also in `config.template.json`): `locations { levels[], rules[{source, pattern}], map{}, labels{} }`,
`groups[{name, match{level: [values]}, doorIds[]}]`, `arming{armAction, disarmAction, armLabel, disarmLabel}`.
Routes: the batch route `POST /api/v1/doors/batch` takes an optional `report: { label }` (and answers with
`reportFile`); `GET /api/v1/arming/report?file=<name>` downloads a report file. Locations are worked out on the page
from the door list; the console runs the same rules (`Get-DoorLocation`) for the location column of the report, and
`tests\fixtures\locations.json` feeds both so they stay equal.

## XProtect maps check: Xprotect-MapCheck.ps1

Read-only check of the classic maps in a Milestone XProtect system (a building picture whose clickable areas, "hot
zones", open the floor plan of each floor, with cameras and doors placed on them). It logs in to the management server
with your Windows login (or `-Credential`) and only reads: the maps, their picture type and size, which floor plan each
hot zone opens, the items on every map by type (other types than cameras / maps / hot zones are listed with sample
names - access control doors show up there), and how many cameras have a Smart Map position. Floor plans are
sensitive: pictures are saved only with `-SaveImages <folder>`, and only inside that folder.

```
powershell -ExecutionPolicy Bypass -File .\Xprotect-MapCheck.ps1 -ManagementServer <management server> -Out mapcheck.txt
```

Add `-SkipCertCheck` when the server certificate is not trusted on this PC. The maps part of the XProtect REST API is
not documented by Milestone; a later XProtect version may change it.

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
`-Terminator LF|None` changes what follows each `;` (default CR LF). The password is never printed or saved.

The connection is TLS 1.2 by default: an AEOS 2023.2 socket interface answered a plain-text login with a TLS alert
(bytes `15 03 03 00 02 02 0A`) and closed it. Add `-SkipTlsCheck` for a self-signed AEOS certificate (the
certificate is always logged). `-Plain` is only for a socket interface without TLS; the password then crosses the
network unencrypted.

## Tabs

- **Doors**: load, filter, and run the mapped actions. Each row shows the result and a **request id**. With locations set up: the location tree, door groups, Arm / Disarm and the arming report.
- **Setup**: license, connection and mappings (above).
- **Raw call**: send any request body to the service and see the response. Use this to explore the web service.
- **Audit**: the last 50 door actions and whether the audit chain is intact.
- **Debug**: live view of the debug log, download of the whole log, diagnostics zip.

## License and trial

The console runs with a license from your supplier. Without a license file it runs as a **30-day trial**, counted from
the first start.

- The header chip shows the state: `Trial - N days left`, `Licensed`, `Trial ended` or `License invalid`. The Setup tab
  has a **License** box with the status, the details of the license, the **AEOS host** (with a Copy button) and
  **Import license file**.
- Send the AEOS host from that box to your supplier. The license is issued for that host name.
- **Import license file**: choose the `license.json` you received. The console checks it first; a file that is not valid
  is refused with the reason and is not saved. A valid file is saved as `license.json` in the folder of the config file
  (`-LicenseFile <path>` uses another place) and takes effect at once.
- A license is valid when: the signature is correct, it is for this product, today is not after its expiry date (no
  expiry date = no end), the host of the AEOS URL (and the socket host, when you set one) is in its host list, and the
  door list has no more doors than the license allows (0 = unlimited).
- With no valid license or trial a red banner shows the reason. The door list, door state, Setup, Audit and Debug stay
  available. Door actions, batch actions, Lockdown and both Raw call tabs are off: the buttons are disabled, and the
  console answers a forced request with HTTP 402 `license_required`.
- The first-start date of the trial is in `trial.json` next to the config file.
- API: `GET /api/v1/license` returns `state` (`trial`, `licensed`, `expired`, `invalid`), `reason`, `daysLeft`,
  `details` and `aeosHost`. `PUT /api/v1/license` takes the text of `license.json`; an invalid file gives 400 and is not saved.

## Debug log and diagnostics (please send these back)

When something fails, **send the debug log or the diagnostics zip to the integrator**. They are written for this.

- **Debug log**: `doorkeeper-debug.log` next to the script (setting *Debug log file* changes the place; it rotates at
  10 MB to `.1`). It is always on. It holds the start-up details (script, PowerShell, .NET, OS, enabled TLS versions,
  settings), every request to AEOS with headers and the full SOAP request and response, the server certificate details,
  every error with all inner exceptions and stack trace, and every call the page makes to this script. The setting
  *Debug level* `basic` leaves the SOAP bodies out.
- **Where the log lines are**: every error on the page ends with `(request id xxxxxxxx)`. That id starts the matching
  lines in the log. Please include the id when you report a problem.
- **Diagnostics zip**: Debug tab, *Create diagnostics zip*. It shows the path of `doorkeeper-diag-<time>.zip` and a
  download link. It contains the debug log, your settings, the audit file and a short environment report.
- **Secrets**: the password is never written. The `Authorization` header is logged as `Basic ****`, a WS-Security
  password as `****`, and the password text itself is replaced by `****` anywhere before a line is written. The log does
  contain the user name, machine name, door names and AEOS responses, so treat it as confidential company data.

## Audit

Every door action (success or failure) is appended to `doorkeeper-audit.jsonl` before the page gets its answer: time (UTC),
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

