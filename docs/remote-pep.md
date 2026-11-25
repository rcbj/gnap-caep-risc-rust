# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether the person a GNAP grant names (a `Person`, or the `Grant` itself) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; this library builds it from your configuration, turns its GNAP sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is `Permit`, `Deny` or `Unavailable`, and `Unavailable` (no policy held yet, iya-sts unreachable or answering badly, or a panic while deciding, which the PEP catches) is a refusal. Every PEP failure is a 403: `decision.http_status()` is 200 for a Permit and 403 for a Deny and for `Unavailable` alike.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| Cargo feature | `pep` | `local` |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is `Unavailable`, and any cached Permit is dropped | decisions continue with the policies held |
| Policy changes | at once | on the `pep-policies-changed` event, or the next poll |
| Decision records | written by iya-sts | sent by the PEP to iya-sts's audit log |

Pick `central` when decisions are infrequent or must reflect a change immediately, and `local` when decisions are on a hot path or must survive a short outage. Both modes give the same answer for the same request (held by [Test that central and local agree](#test-that-central-and-local-agree)): `local` maps the request through the realm's catalogue exactly as iya-sts does, and its engine is held to iya-sts's conformance corpus.

## Before you start: set up iya-sts

You need an iya-sts release with embedded-PEP support (iya-sts #2026, #2027 and #2028). The steps below use the management API; `$API` is `https://<host>/realm/<realm>/admin-api` (or `https://<host>/admin-api` for the default realm) and `$TOKEN` a token for it with write access. Every step has a console equivalent, named after it.

```bash
api() { curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$2" "$API/$1"; }
```

### 1. Register the application

Register the GNAP client in iya-sts as usual; `scripts/configure_iya_sts.py` does it for the demo, and with `--pep` (local; or `--pep central`) does steps 2 to 6 for the demo too (see [The demo](#the-demo)). Note its identifier: it is the `application` the PEP is bound to (the configuration's own `application` by default).

### 2. Create the PEP's service account

The PEP signs in as a service account of its own, never as a person or as the application:

```bash
api users/create '{"username":"pep-orders","invent":false,
  "credential":"none","serviceAccount":true,"owners":["admin-write"],
  "attributes":{"cn":"pep-orders","displayName":"pep-orders"}}'
api groups/add-member '{"group":"remote-peps","member":"pep-orders"}'
```

Console: **Users → New user** (tick **Service account**), then the `remote-peps` group's **Add member**.

### 3. Make the PEP's key, certify it and bind the PEP

Generate the key where the application runs. Only the certificate request leaves the machine:

```bash
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out pep-key.pem
openssl req -new -key pep-key.pem -subj /CN=pep-orders -out pep-key.csr
api xacml/issue-pep-credential "$(jq -n --rawfile csr pep-key.csr \
  '{name: "pep-orders", csr: $csr, application: "<application id>"}')"
```

`application` binds the PEP to the application in the same call (`POST /admin-api/xacml/set-pep-application` does it on its own). An EC P-256 key is preferred; RSA of 2048 bits or more is accepted. **The key must be the PEP's own**: this library refuses a configuration where it is the client instance key (`privateKey`, behind every `httpsig`, `jwsd` or `mtls` proof).

Console: **Protocols → XACML → Remote PEPs**, **Certify the key**, then the PEP's Overview, **Embedded in an application**.

### 4. Declare the claims your policy reads

The PEP sends a subject's claims only through the realm's AuthZEN attribute catalogue: a claim with no catalogue row is not sent (iya-sts would refuse the whole request). Add one row per claim your policy uses, on **Protocols → XACML → AuthZEN** or with `POST /admin-api/xacml/authzen/set-attribute`. For example, to make `acr` available as `urn:example:acr`:

```bash
api xacml/authzen/set-attribute '{"object":"subject","property":"acr","attributeId":"urn:example:acr"}'
```

which is the row

| `object` | `property` | `attributeId` |
|---|---|---|
| `subject` | `acr` | `urn:example:acr` |

The same applies to `resource.properties`, `action.properties` and `context` members you put on an `Access`. iya-sts's [AuthZEN page](https://rcbj.github.io/iya-sts/v1.2.0/authzen.html), *The realm's conversion rules*, describes the rows.

### 5. Write the policy

The policy that decides is the application's own fine-grained authorization policy when the application enforces fine-grained authorization, and otherwise the realm's root policy. A `local` PEP is sent that policy and everything it references, and nothing else. The subject's id arrives as XACML's `subject-id`, the action's name as `action-id` and the resource's id as `resource-id`; anything else comes through the catalogue rows of step 4, or from iya-sts's PIP for attributes on the person's directory entry. The resource's type arrives as `urn:sts:xacml:authzen:resource-type`.

For an application that enforces no fine-grained authorization, a root that permits `read` on an `order` when the person's `acr` arrived, and denies everything else, can be written in ALFA (the console's **Policies** tab does the same):

```bash
api xacml/import-alfa "$(jq -n --arg alfa '
namespace orders {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute rtype { category = resourceCat
        id = "urn:sts:xacml:authzen:resource-type" type = string }
    attribute acr { category = subjectCat id = "urn:example:acr" type = string }
    policy ordersRoot {
        id = "urn:example:orders"
        apply firstApplicable
        rule readOrder {
            permit
            target clause act == "read"
            target clause rtype == "order"
            condition integerGreaterThan(stringBagSize(acr), 0)
        }
        rule otherwise { deny }
    }
}' '{name: "orders", alfa: $alfa}')"
api xacml/set-root '{"name":"orders"}'
```

Every change to that policy, or to which policy is the root, is sent to a `local` PEP as `pep-policies-changed` (step 6).

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll, and the application's page in the console warns about it.

## Build with the feature

```toml
gnap-caep-risc = { version = "…", features = ["pep"] }    # central
gnap-caep-risc = { version = "…", features = ["local"] }  # local (includes central)
```

Without the feature a `pep` section is refused when the configuration is read, rather than silently ignored. A section that names no `mode` is `local`, so a build with `pep` alone must name `"mode": "central"`; otherwise it is refused the same way.

## Configure

Add a `pep` section to `gnap.json`. The PEP is off unless it is present.

```json
"pep": {
  "name": "pep-orders",
  "mode": "local",
  "assertionKey": "pep-key.pem"
}
```

| Member | Default here | What it is |
|---|---|---|
| `name` | required | The PEP's service account (step 2). |
| `mode` | `local` | `local` (the PEP pulls its application's policies, caches them in memory and decides in process) or `central` (it asks iya-sts for every decision). |
| `assertionKey` | required | The PEP's private key in PEM: a path; a relative one is read from the configuration file's directory, like `privateKey`. The file is re-read when it changes. |
| `pdpUrl` | the iya-sts realm the grant endpoint belongs to: `https://sts/realm/acme/gnap` gives `https://sts/realm/acme`, and `https://sts/gnap` gives `https://sts` | iya-sts, with `/realm/<id>` for a realm. |
| `application` | the configuration's `application` | The application the PEP is bound to (step 3). |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | on when this library runs a Shared Signals receiver (signals on and a transmitter configured) | Whether a signal stream hands over policy-change events. Without one, `local` polls at `pollIntervalMs`. |
| `pollIntervalMs` | 15000 | `local` without a signal stream. |
| `fallbackPollMs` | 300000 | `local` with one, in case an event is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a Permit for this long, at most 60000. The policy-change event clears it, and so does a failed evaluation or a failed heartbeat: no cached Permit is served until the service answers an evaluation again. |
| `supportedObligations` | `[]` | The obligation types your application discharges (see *Obligations*). |
| `decisionRecords` | `true` | `local`: send each decision to iya-sts's audit log. |
| `tlsCa` | the library's `tlsCa` | PEM trust anchors for iya-sts's TLS. |
| `timeoutMs` | 10000 | Per request to iya-sts. |

An unknown member is refused, so a misspelt one doesn't quietly fall back to a default. `Client::create` and `from_file` start the PEP. `Client::new` does not, because starting can fail and `new` can't report it; call `client.pep().unwrap().start()` yourself if you use it.

## Decide

```rust
use gnap_caep_risc::Client;
use gnap_caep_risc::pep::{Access, Decision};

let client = Client::from_file("gnap.json")?; // registers the PEP and, in local mode, pulls

// After the grant is approved (and `ensure_fresh` if the token may have expired):
let access = Access::new("read", "order", order_id);
let decision = client.decide_grant(&grant, &access);
let status = decision.http_status(); // 200 for a Permit, 403 for anything else
match decision {
    Decision::Permit { obligations, .. } => serve(obligations),
    Decision::Deny { why } => forbidden(status, &why),          // 403
    Decision::Unavailable { why } => forbidden(status, &why),   // 403: fail closed
}
// For a Person you hold yourself: client.decide(&person, &access)
```

`Access::new(action, resource_type, resource_id)` carries the AuthZEN action and resource. Add `resource_properties`, `action_properties` or `context` members as your policy needs them, each declared in the catalogue (step 4). The PEP always sets `context.application` to the bound application, whatever you put there.

**The subject** comes from the sign-in, never from a request header:

- **id:** the username: the user part of the grant's `account` subject identifier (iya-sts builds it from the directory username), else iya-sts's `username` claim in the ID token assertion, else its `preferred_username` (a `profile` claim, there only when that scope was granted), else `sub` (which can be pairwise, so it's the last resort).
- **properties:** the ID token's claims (`acr`, `amr`, `auth_time`, …), with `acr` and `amr` filled from the `Person` when the claims lack them.

Only the properties the catalogue declares are sent.

**Ended sessions.** `client.decide_grant(&grant, &access)` is a Deny without asking when the grant has ended: it has no subject, this client revoked it, or its access token has expired (rotate it with `ensure_fresh` first).

**Without a `pep` section**, every decision is `Unavailable`.

**`decide` never fails.** No policy held, a service that can't be reached or answers badly, an engine fault, or a panic while deciding is `Unavailable` (a panic's reason goes to `status().last_error`), never a Permit and never an unwinding thread. Take the HTTP status from `http_status()` rather than choosing one per arm; 401 for nobody signed in is your question, asked before the PEP's.

### Obligations

A `Permit` can carry obligations, which your application must carry out before it grants the access (for example a `step-up` to a stronger `acr`). The PEP only hands you obligations of types you list in `supportedObligations`. A Permit carrying any other obligation is turned into a Deny, so an obligation is never silently dropped. `advice` can be ignored; `central` carries it only while the realm's `authzen.returnReasons` is on.

```json
"pep": { "name": "pep-orders", "assertionKey": "pep-key.pem", "supportedObligations": ["step-up"] }
```

## Receive policy-change events

In `local` mode, and in `central` mode with a Permit cache, the PEP wants to hear when the policies change. Give the receiver the PEP in `ReceiverOpt::pep`.

```rust
let mut opt = ReceiverOpt::new(&transmitter_url, on_end);
opt.pep = client.pep().cloned();
let receiver = SignalsReceiver::new(opt)?;
```

The receiver then asks its stream for `urn:iya:sts:secevent:event-type:pep-policies-changed`, verifies each SET like every other one, and hands the event to the PEP. A stream that already exists (made before the `pep` section was added, or while the PEP was `central`) is updated with `PATCH` to ask for the event too; if the transmitter refuses, the receiver still starts, the refusal goes to `ReceiverOpt::on_error` (standard output without one), and the PEP's heartbeat reports the event as `excluded`. The event is only a hint: the PEP pulls with its own credential and never trusts the event's contents. An event naming another PEP is ignored.

The receiver also adds each signed-in person to its stream (Add Subject at sign-in, Remove Subject after their last sign-out; `ssf.addSubjects`, default on; see the README's *Subjects*), so the stream carries events only about the people signed in to this application. Because a stream that names subjects carries only events about them, a receiver whose PEP wants events also adds the application itself (`{format: opaque, id: <application>}`, the `application` member of `pep-policies-changed`'s subject) when it starts, and never removes it.

The receiver also tells the PEP how its stream is doing, which the heartbeat reports and the PEP's own policy poll follows: `requested` (or `excluded`) once it starts and after every good poll, `down` after a failed poll and once `stop()` is called. While it is `down` the PEP polls its policies itself.

## Operate it

- **Health.** `pep().unwrap().status()` reports whether the PEP is registered and running, whether it holds a policy (and which sync token), its decision counters and its current problems. It holds no secret, so it's safe on a health page.
- **In the console.** The PEP appears under **Protocols → XACML → Remote PEPs** with its kind (`embedded`), application, mode, protocol version and whether its stream carries policy-change events. The application's page lists the PEPs bound to it.
- **Rotating the key.** Generate a new key, certify it with `issue-pep-credential` (add `revokePrevious: true` to retire the old one), replace the file, and call `pep().unwrap().reload_key()` (or wait up to 30 s). The tokens bound to the old key are dropped.
- **Audit.** In `local` mode each decision becomes an audit row in iya-sts (`authzen.remote.decision`). In `central` mode iya-sts records its own.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| Every decision `Unavailable`, `status().registered` false, a problem mentioning 403 | The PEP's entry has no binding, or is bound to another application (iya-sts `STS-XACML-0338`, `0339`). Repeat step 3 with the right `application`. |
| `Unavailable` and a problem naming the token endpoint (`invalid_grant`) | The key isn't certified for this account, or the account isn't in `remote-peps` (steps 2 and 3). |
| `Unavailable` with "no policy is held yet" (`local`) | The first pull hasn't succeeded. Check `status().last_error`: a 403 on the policy pull (`STS-XACML-0343`) means the PEP isn't registered as an embedded `local` PEP bound to that application. |
| A registration refused with 400 (`STS-XACML-0340`) | The iya-sts release doesn't support this PEP's protocol version. Upgrade iya-sts or this library. |
| `Deny` saying the evaluation was refused (`local`: "refused (STS-AUTHZEN-0004)"; `central`: "the service refused the evaluation: invalid_request …") | A resource, action or context property you sent has no catalogue row (step 4). Subject claims without a row are dropped, not refused. |
| `Deny` although the policy should permit | The policy reads a claim that has no catalogue row, so it never arrives (step 4). Or a Permit carried an obligation type missing from `supportedObligations`. |
| Policy changes take minutes to apply (`local`) | The stream doesn't carry the event: check the console's *policy-change events* column, `ssfAllowedEvents` (step 6), and `ReceiverOpt::on_error` (standard output without one) for a refused stream update. |
| The configuration is refused for the assertion key | It is one of this library's own keys. The PEP needs a key of its own. |

## Test that central and local agree

`src/tests/authzen_cases.json` is this library's own AuthZEN table: catalogue rows (typed values, bags, dotted paths, short category and datatype names), policies in ALFA (with the XACML iya-sts stores for each), people with ID token claims, and evaluation cases, each with the answer the host should see. `src/tests/authzen.rs` asks every case through `Client::decide` or `Client::decide_grant`.

- `docker build --target test .` runs it in `local` mode against a stub realm serving the table.
- `python3 scripts/live_iya_sts.py --authzen` provisions the table into a fresh iya-sts (a `central` and a `local` PEP per application, each with its own key) and runs every case through both. It fails unless central, local and the table all agree, and prints `cases`, `centralEqualsLocal`, `bothEqualExpected` and each mismatch. `--write-xacml` takes iya-sts's stored XACML into the table after you change an ALFA policy.

The live run sets `authzen.returnReasons` on in its realm, because iya-sts sends a `central` PEP the answer's advice only while that setting is on. Do the same in your realm if your policies give advice you act on; without it `central` hands no advice while `local` does.

Against iya-sts `feature/2028` with iya-pep `c0d61ca`, all 58 cases agree: `central` == `local` == the table. The run first found three differences, each fixed where it lived: advice dropped by `central` (iya-pep reads `context.advice` now), an enforcing application's policy reference left unresolved by `central` (iya-sts #2027), and the `urn:sts:xacml:fga:*` facts missing in `local` (iya-pep adds them for an application in the catalogue's `fgaApplications`).

## The demo

Built with `local` (the Dockerfile does), the demo protects `GET /orders/<id>` with the PEP when `demo/gnap.json` has a `pep` section: 401 without a sign-in, 200 on a Permit, and 403 on a Deny and on `Unavailable` (any PEP failure is a 403: the page says the PEP could not decide). `GET /attribute-protected` is decided the same way on a directory attribute rather than a claim: the demo application's policy permits `read` on `attribute-protected` when the person's `attr1` is `abc123`, which the PEP asks iya-sts's PIP for (`POST /xacml/pip`). `GET /live-status` carries the PEP's `status()` under `pep`.

Its signed-in page has a **Policy enforcement** tab (`/?tab=pep`) showing what the PEP reports, refreshed every two seconds (`pep.js` redraws it from `GET /pep-status.html` and keeps a pane you closed closed):

- **Decisions:** how many, allowed, denied, unavailable, stopped by an obligation, and the mean and slowest time per decision (plus the Permit cache in `central` mode).
- **Cached policy:** policies held, when the cached policy last changed, the last and the next scheduled pull, pulls (changed, failed), policy-change events, the catalogue claims sent, and the policy set's and catalogue's versions.
- **The PEP:** name, mode, application, iya-sts, registered, running and uptime, whether the stream carries policy-change events, the protocol version and the key's thumbprint.
- **Control plane:** heartbeats (last, next, failed), registrations, and decision records queued, sent and dropped.
- **Try it:** links to `/orders/42` and `/attribute-protected`.

`GET /pep-status` answers the same as JSON for a dashboard of your own; both answer 401 without a session. Every number comes from `pep().unwrap().status()`, which your application can read the same way. With no `pep` section the tab says so.

One command sets it up:

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json --pep central   # or --pep (local)
```

It registers the client, then does steps 2 to 6: the service account `pep-gnap-demo` (`--pep-name`), a key in `demo/generated/pep-key.pem`, certified and bound to the demo's application, the catalogue row `subject.acr`, and the application's own policy, which it enforces; the realm root is untouched. It writes `pep` (`name`, `mode`, `assertionKey: generated/pep-key.pem`) into the configuration. Run again, it keeps the account and key and switches the mode; the policy is written again while it is the script's own (PolicyId `urn:example:gnapdemo-orders`), so a new rule reaches an existing install, and a policy under any other PolicyId is left as it is. The test user gets `attr1=abc123`; the script defines the realm's custom attribute `attr1` first, with a token carrying `admin:security` minted for that one call. Enforcing the demo application decides nothing at GNAP issuance, because its grant asks for plain access rights, not an `authorization_details` type it declares.

Live (`scripts/live_iya_sts.py --pep`, which checks `/orders/42` only, iya-sts `feature/2028` at `a6cb55cb3`, before `/attribute-protected` and the `attr1` setup were added): `central` and `local` give 200 for read and 403 for write, and after the application's own policy changes, `local` applies it by `pep-policies-changed` in 1.1 s. That needs iya-sts's GNAP subject scope to let the event's application subject through to a GNAP client's stream (`a6cb55cb3`); before it, the event was refused (`STS-SSF-0029`) and `local` waited for its next heartbeat.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-rust#readme): the crate's own API and every configuration member.
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html), *An embedded PEP's application*: the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
