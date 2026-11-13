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

Options: `-BehindProxy -PublicUrl https://<name>` (run behind IIS, see "Hosting on IIS"), `-Port 8765` (default), `-ConfigFile <path>` (default `doorkeeper.json` next to the script, created on first
run; an existing `aeos-console.json` from an older version is used when `doorkeeper.json` is missing), `-NoBrowser` (do not open the browser). The page opens on `http://localhost:8765/`. Press Ctrl+C in the window
to stop. Only this PC can reach the page.

Files created next to the script: `doorkeeper.json` (your settings), `doorkeeper-audit.jsonl` (audit),
`doorkeeper-debug.log` (debug log), `doorkeeper-diag-<time>.zip` (diagnostics, on request),
`doorkeeper-users.json` (page settings per AEOS user), `doorkeeper-state-cache.json` (last known door states), `doorkeeper.lock` (single-instance lock) and, once a server account is set, `doorkeeper-server-account.bin` / `.json`.

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

## Operators and admins

Several people can use DoorKeeper, each logging in and out with his own AEOS account (every browser has its own session; on a single PC the page is served on this PC only, behind IIS see "Hosting on IIS"). **The password is checked at login.** With the socket interface set up (a login command that
holds `{{password}}`) **and a non-empty *Login success pattern*** (an empty pattern is no check: any reply would pass), DoorKeeper opens one short socket session with only the login; the reply must match the pattern. Otherwise, when the *List doors* action is mapped, it makes one list doors call; **only an affirmative answer (HTTP 2xx and no SOAP fault) accepts the login**, any other status or a fault is a refusal. A refused login answers "AEOS refused the user or password", keeps nothing, and is written to the audit
file (`login`, not OK, with the typed user name). While neither is set up yet (first setup) nothing can be checked and the
login is accepted on the local console; **behind IIS (`-BehindProxy`) such a login is refused** (503 "AEOS login cannot be checked: set up the AEOS connection on the server first."). If AEOS cannot be reached, the login is refused with that reason: an admin who locked himself out this
way edits `doorkeeper.json` (`"access": { "admins": [] }`) and restarts.

- **Admin** = an AEOS user name in *Setup, Admins* (one per line, upper or lower case does not matter). **Operator** =
  everybody else. An operator sees the Doors tab only (no Setup, Raw call, Audit, Debug) and can load doors, see states,
  run actions, batch, Arm / Disarm and Lockdown, and change his own view (sort, rows per page, filter).
- **First run:** (behind IIS the rule is different: with `-BehindProxy` an empty list gives nobody admin rights, see "Hosting on IIS".) While the admin list is empty every user is an admin and a red banner says so: "No admin is set: every user
  can change settings. Add admins on the Setup tab." The first list needs a logged-in user and must hold his own name.
- **Enforced on the server**, not only hidden: an operator (or a visitor who is not logged in once admins are set) gets HTTP
  403 `forbidden_role` on saving the config (which also covers groups and map import), Load WSDL, both raw calls, the debug
  log and diagnostics zip, the audit file and its export, license import and alias changes.
- You cannot lock yourself out: the admin list cannot be emptied and must keep your own name (another admin can remove it).
- "From where": every audit line records the **computer name** of the PC that runs DoorKeeper next to the Windows user and
  the AEOS user. Reaching the console from other PCs (network listener, HTTPS, per-browser sessions) is not part of this
  version; it would be a separate security change.

## Hosting on IIS (many operators)

DoorKeeper can run behind IIS so that many operators open one HTTPS address, for example
`https://doorkeeper.example.org`, each in his own browser with his own AEOS login. IIS holds the HTTPS certificate and starts
DoorKeeper through the Microsoft **HttpPlatformHandler** module; DoorKeeper still listens on `localhost` only, IIS is the only
way in. HttpPlatformHandler cannot start a child that listens through HTTP.sys (it answers 502.3), so DoorKeeper binds the port
HttpPlatformHandler gives it (`%HTTP_PLATFORM_PORT%`, option `-Port`) with a small built-in TCP relay on `127.0.0.1`, and the web
listener itself runs on `http://localhost:<InternalPort>/` (option `-InternalPort`, default 8765). The relay copies each
connection both ways and allows about 200 at a time. Without `-BehindProxy` nothing of this applies.

**Status: lab-proven on IIS 10 (Windows Server 2025) with this README's `web.config`:** HttpPlatformHandler starts DoorKeeper
directly (built-in relay), the `Host` rewrite, the handlers unlock, `loadUserProfile`, two operators at the same time, admin and
operator roles, the client address in the audit, the server account (DPAPI, file ACL) and an app pool recycle. The Windows user
is not available behind IIS.

### What changes with `-BehindProxy`

- **One session per browser.** The login creates a session: a random 32-byte id in the cookie `dk_session` (HttpOnly, Secure,
  SameSite=Strict), its own page key (header `X-Console-Token`) and the AEOS credential of that user, kept in memory only.
  Every role check and every AEOS call uses the credential of the session that asked. An operator who is idle for
  `access.idleMinutes` (default 15) or has been logged in for 12 hours must log in again; logout ends the session at once.
  A restart of DoorKeeper ends all sessions.
- **Origin** must equal `-PublicUrl` exactly; **the client address** (header `X-DK-Client-IP`)
  is read only on requests from `127.0.0.1`, and only this header, never `X-Forwarded-For`. Behind IIS every request comes from `127.0.0.1`, so a browser could send this header itself: the **URL Rewrite rule in the sample `web.config` is REQUIRED**, it overwrites it on every request. Without it the audit "from where" cannot be trusted. It goes into the audit. **The Windows user is not available behind IIS** (`{LOGON_USER}` is empty when the rule runs), so DoorKeeper does not read any such header and `windowsUser` in the audit stays empty.
- **Door actions run with the operator's own AEOS account**, so the AEOS log names the operator too.
- **Batch actions, Arm / Disarm and Lockdown run as background jobs** (one job per operator at a time); the page shows the
  progress and the report at the end, so a long batch never blocks the other operators.
- **Door lists per session.** Each session keeps the door ids of its own last successful *Load doors*; the live states and the door routes (state, action, batch) cover only those doors. Before a session has loaded doors it gets no states.
- **Reports and jobs belong to their operator.** The arming report file name holds the job id and is created with CreateNew; only the operator of the job (or an admin) can read the job or download its report.
- **Audit v4.** Every field of a line (the fault text too) is covered by its hash.
- **Single instance.** DoorKeeper takes an exclusive lock on `doorkeeper.lock` in its data folder and stops with a clear message
  when another instance holds it (two instances would break the audit hash chain and double the polling). After an IIS
  recycle the new process waits up to 8 seconds for the old one to go.
- **Login rate limit:** 5 failed logins in 5 minutes block that user from that address for 5 minutes (HTTP 429, audited as
  `login-blocked`).
- **Security headers** on every answer: `Content-Security-Policy` (the page: this site only; the API: nothing),
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- **No admin until the file says so.** With `-BehindProxy` an empty `access.admins` list gives NOBODY admin rights: every
  session is an operator and Setup changes are refused with 403 `forbidden_role`. (Without `-BehindProxy` the first-run rule
  stays: while the list is empty every user is an admin.) The page shows: "No admin is set. An administrator of the server
  must add AEOS user names to access.admins in the DoorKeeper config file and restart the site." So the first admin is set by
  an administrator **on the server**: edit `doorkeeper.json` in the DoorKeeper folder, put the AEOS user name(s) into
  `"access": { "admins": [ "<aeos user>" ] }`, save, and restart the app pool (IIS Manager, Application Pools, Recycle). The
  admin can then add the other admins on the Setup tab.

### Install steps

0. **First setup on the server, without IIS:** run `DoorKeeper.ps1` on the server **without `-BehindProxy`** (as in "Run"), open `http://localhost:8765/` on the server itself, and do the first setup: the AEOS connection (URL, list doors, socket and its login command with a **login success pattern**), the Door state checks and the admin list. Stop it, then start the IIS site. Behind IIS no login is accepted until the AEOS connection can check it.
1. **Server:** Windows Server with IIS, the HTTPS certificate of the customer bound to the site, the **HttpPlatformHandler**
   module (Microsoft download, installed once). Windows PowerShell 5.1 is part of Windows.
2. **Folder:** copy `DoorKeeper.ps1` to its own folder, for example `C:\DoorKeeper` (this is also the data folder: settings,
   audit, debug log, lock file, server account). Give the app pool identity modify rights on it:
   `icacls C:\DoorKeeper /grant "IIS AppPool\DoorKeeper:(OI)(CI)M"` and create `C:\DoorKeeper\logs`.
3. **App pool** `DoorKeeper`: No Managed Code, identity **ApplicationPoolIdentity**, **load user profile = true** (DPAPI needs
   it for the server account), start mode **AlwaysRunning**, idle time-out **0**, **overlapped recycle OFF**:
   ```
   appcmd add apppool /name:DoorKeeper /managedRuntimeVersion: /processModel.identityType:ApplicationPoolIdentity ^
     /processModel.loadUserProfile:true /startMode:AlwaysRunning /processModel.idleTimeout:00:00:00 ^
     /recycling.disallowOverlappingRotation:true
   appcmd add site /name:DoorKeeper /physicalPath:C:\DoorKeeper /bindings:https/*:443:doorkeeper.example.org
   appcmd set app "DoorKeeper/" /applicationPool:DoorKeeper
   appcmd set site /site.name:DoorKeeper /applicationDefaults.preloadEnabled:true
   ```
   Bind the certificate to the https binding in IIS Manager (or by script:
   `netsh http add sslcert ipport=0.0.0.0:443 certhash=<thumbprint> appid={<any GUID>}`). **Unlock the handlers section once** (it is locked by default, and
   a `web.config` with a `<handlers>` entry is refused until then):
   ```
   appcmd unlock config -section:system.webServer/handlers
   ```
   `loadUserProfile:true` is needed for two things: DPAPI (the server account) and the C# compile (`Add-Type`) that DoorKeeper
   does at start; with `false` both fail.
4. **`web.config`** in `C:\DoorKeeper` (sample; replace the name and the paths):
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <configuration>
     <system.webServer>
       <handlers>
         <add name="httpplatformhandler" path="*" verb="*" modules="httpPlatformHandler" resourceType="Unspecified" />
       </handlers>
       <httpPlatform processPath="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                     arguments="-NoProfile -ExecutionPolicy Bypass -File C:\DoorKeeper\DoorKeeper.ps1 -Port %HTTP_PLATFORM_PORT% -InternalPort 8765 -NoBrowser -BehindProxy -PublicUrl https://doorkeeper.example.org"
                     processesPerApplication="1" startupTimeLimit="60" startupRetryCount="3" requestTimeout="00:05:00"
                     stdoutLogEnabled="true" stdoutLogFile="C:\DoorKeeper\logs\httpplatform-stdout" />
       <rewrite>
         <rules>
           <!-- REQUIRED: overwrites the client address header on EVERY request (a browser can send its own), and sets Host to what
                the internal listener accepts: IIS forwards the public name, HTTP.sys answers 400 Invalid Hostname to it.
                Keep localhost:8765 equal to -InternalPort above. -->
           <rule name="DoorKeeper client info" stopProcessing="false">
             <match url=".*" />
             <serverVariables>
               <set name="HTTP_X_DK_CLIENT_IP" value="{REMOTE_ADDR}" />
               <set name="HTTP_HOST" value="localhost:8765" />
             </serverVariables>
             <action type="None" />
           </rule>
         </rules>
       </rewrite>
     </system.webServer>
   </configuration>
   ```
   The rule needs the IIS **URL Rewrite** module and the two server variables allowed once for the site:
   ```
   appcmd set config "DoorKeeper" -section:system.webServer/rewrite/allowedServerVariables /+"[name='HTTP_X_DK_CLIENT_IP']" /commit:apphost
   appcmd set config "DoorKeeper" -section:system.webServer/rewrite/allowedServerVariables /+"[name='HTTP_HOST']" /commit:apphost
   ```
   DoorKeeper does no parsing of `Host` itself. `-PublicUrl` must be exactly what the browser shows (scheme, name,
   port if not 443), otherwise every request answers 403 "Origin not allowed".
5. **First start:** open `https://doorkeeper.example.org/`, then follow "No admin until the file says so" above. Set the
   server account (next section) and the settings of the Door state tab as on a single PC.

**First request after a start (lab-proven):** after an app pool recycle or an IIS start the DoorKeeper process starts only on the
first request, so the first page load takes a few seconds (the compile and the start) and live door states resume after it.
A recycle keeps one instance (the lock file), the sessions end with it (operators log in again), and the audit chain stays valid.

### Server account (live door states)

An admin enters it once on Setup, **Live door states (server account)**: an AEOS user and password, checked against AEOS
before they are kept. With it the console reads **all door states in the background** (a separate worker, never the
request loop), in sessions of *Doors per socket session*, round after round with a pause of `doorState.pollSeconds`
(default 30) between rounds, and a door that was just acted on is read again at once. The page asks for the changes since its
last version every 3 seconds, so every operator sees the states **without pressing Load**. A door's buttons stay disabled
until its state is fresher than `doorState.freshSeconds` (default 120), the rule "no action before a fresh state" stays.
Without a server account the page reads the states itself when the operator loads the doors, as before.

- **The server account only reads.** Every door action runs with the operator's own AEOS account. Create a **dedicated AEOS
  user with the fewest rights** that allow the login and the state queries (`isLocked`, `isUnlocked`).
- **Stored encrypted:** DPAPI, scope CurrentUser of the Windows account that runs DoorKeeper (the app pool identity), with
  fixed entropy, in `doorkeeper-server-account.bin` in the data folder; the file's access list is the app pool identity and
  Administrators only, inheritance off. Only DoorKeeper's own process can decrypt it. The password is never sent to a browser,
  never logged and never audited; the page shows only "Set by <admin> at <time>, last login OK at <time>" and offers
  Replace and Remove. Every change writes an audit line (`server-account-set`, `server-account-remove`).
- If the stored account cannot be decrypted (for example the app pool identity was changed), Setup says **"Server account
  must be entered again."**, the poller stays off and the console keeps working. Without `loadUserProfile=true` the store
  fails: Setup says so.
- Polling a large site loads AEOS: for 1893 doors one round is about 4 socket sessions of 500 doors; raise `pollSeconds` or
  lower the session size if AEOS is busy. Measure on site.

## Aliases (friendly door names)

The AEOS id or name of a door is often cryptic. An **alias** is a friendly name for a door: the Doors table has an
**Alias** column right after the checkbox, the filter box finds doors by alias too, and the confirm questions, the arming
report CSV (`door_alias`) and the audit lines show it next to the name.

- Admins edit an alias in place: click the Alias cell, type, **Enter** saves, **Esc** cancels. An empty text removes it.
  Max 200 characters, no control characters.
- **Setup, Aliases:** *Export doors as CSV* writes `id;name;alias` (semicolon separated, load the doors first); fill in the
  alias column and *Import aliases*. A line may be `id;alias`, `name;alias` (when the id is not known and the name is
  unique) or the three exported columns. Unknown doors are skipped and counted. Aliases are stored in `doorkeeper.json`
  (`"aliases": { "<door id>": "<alias>" }`).

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

**Fast status.** The rule stays: **a door's buttons stay off until the fresh state of this load is known**, and the batch
buttons, Arm / Disarm and Lockdown stay off until every door they would touch has a fresh state. To make that quick:

- *Load doors* paints the **last known states** at once, muted, with "last known HH:MM" in the tooltip (DoorKeeper keeps the
  last state of every door in memory and in `doorkeeper-state-cache.json`). They only paint; they never switch a button on.
- The page then reads the states in chunks of 100 doors (one socket session each): first the doors on the shown page, then
  the rest of the filtered list, then all others. Every chunk paints as it arrives and switches on the buttons of its doors.
  The progress text is "State 300 of 1893 read". A door whose read failed (`?`) stays off; *Refresh state* tries again.
- For one door the state checks stop at the first match: a Locked door needs one command, not two.
- No parallel socket sessions: it is not known whether AEOS allows them. Measure on site first.

**Sorting.** Every column header except the checkbox and Actions sorts: first click ascending, second descending, third back
to the list order; an arrow shows the order. Text sorts case-insensitive and natural (Gate 2 before Gate 10); State sorts by
its label; location columns by their value; doors with an empty value come last. Sorting applies before paging, and a new
sort goes to page 1.

**Per user.** Rows per page, the sort, the last filter text and the selected location node are stored on the server per AEOS
user (`doorkeeper-users.json`) and come back at the next login. When nobody is logged in the browser's own storage is used
for the rows per page.

**Pages.** The table shows *Rows per page* doors (25, 50, 100, 250, 500 or All; default 100, remembered per user) with
First / Previous / Next / Last above and below it and "Doors 1-100 of 1893, page 1 of 19". The pages
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
not documented by Milestone; a later XProtect version may change it. When `/IDP/connect/token` answers 401 for a valid
account, try another name of the same server (short name, full name): on one site one name answered 401 and another
worked.

- `-Find <text>` prints every placed item whose name contains the text, with its map and type (for example a door name
  from the DoorKeeper list, to see which item type the doors are), and every map whose definition holds the text: on
  site, doors that Smart Client shows and controls on a floor plan were not in the maps API's item list.
- `-DumpMap <map name>` writes the definition of the first map whose name contains the text to `-DumpFile` (default
  `mapdump.xml`), picture data removed, to see how its items (doors included) are stored and positioned.
- `-ItemsFile items.jsonl` writes every placed item as one JSON line: map, map id, type and the item as the server
  returns it, position fields included. Like the floor plans, this file describes the site: keep it there.

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

- **Doors** (everybody): load, filter, sort, and run the mapped actions. Each row shows the alias, the result and a **request id**. With locations set up: the location tree, door groups, Arm / Disarm and the arming report.
- **Setup** (admins): license, admins, aliases, connection and mappings (above).
- **Raw call** (admins): send any request body to the service and see the response. Use this to explore the web service.
- **Audit** (admins): the last 200 matching audit lines with a filter and CSV export, and whether the audit chain is intact.
- **Debug** (admins): live view of the debug log, download of the whole log, diagnostics zip.

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

Every door action (success or failure), every login (also a refused one) and every logout is appended to
`doorkeeper-audit.jsonl` before the page gets its answer: time (UTC), the **computer** name, Windows user, AEOS user,
action, door (id, name and **alias**), HTTP status, result and fault text. So the file answers who opened which door, when,
and from which PC. Each record carries the hash of the previous one (SHA-256 chain), so a changed or deleted line breaks the
chain; the Audit tab shows "Chain OK" or "CHAIN BROKEN". New lines have `"v":4` (older v1-v3 lines still verify) and the hash covers every field, among them the computer name,
the alias and the **client address** (`clientIp`: the address IIS passed on; `windowsUser` stays empty behind IIS: the Windows user is not available there); older lines (v1, v2) keep their old hash and still verify. Server account changes (`server-account-set`,
`server-account-remove`) and blocked logins (`login-blocked`) are audited too.

The Audit tab (admins) filters by user (AEOS or Windows), door (name, alias or id), action (*Opened* = unlock or provide
access, one action, login, logout) and UTC date range, and exports the matching lines as CSV
(`time_utc,computer,client_ip,windows_user,aeos_user,action,door_id,door_name,door_alias,http_status,ok,fault,batch`). The chain check
always covers the whole file, whatever the filter.

## Security notes

- The page listens on `localhost` only. Every call from the page carries the page key of the session (a random per-start key before the
  login) and the `Origin` is checked, so another web page in your browser cannot trigger a door action through this port.
- The routes that take doors (state, action, batch) use only the door **id** from the page; name and extra come from the door
  list the server read from AEOS itself. An id the server does not know is refused ("Load doors again").
- No data is sent anywhere except to the AEOS URL you configured. No CDN, no telemetry.
- Use HTTPS to the AEOS server. With plain `http://` the password travels unencrypted (the page warns).
- Certificate validation is on unless you switch it off per the TLS step above.
- The debug log and diagnostics contain no password but do contain operational details; do not post them publicly.
- Stop the script (Ctrl+C) when you are done.

