// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gnap_caep_risc::{Client, EndFn, Events, Grant, Person, ReceiverOpt, SignalEvent, SignalsReceiver, TrackedSession};
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct SessionRecord {
    person: Option<Person>,
    grant: Grant,
}

struct State {
    client: Option<Arc<Client>>,
    client_err: String,
    sessions: HashMap<String, SessionRecord>,
    receiver: Option<SignalsReceiver>,
    receiver_state: String,
    /// The Shared Signals events received, oldest first, at most MAX_EVENTS.
    events: Vec<LiveEvent>,
    event_seq: u64,
    latest: Option<Grant>,
    /// Per local session: the access token rotations seen.
    rotations: HashMap<String, Rotations>,
}

/// The access token rotations of one sign-in: how many, and the last one's
/// time (seconds since the epoch).
#[derive(Clone, Default)]
struct Rotations {
    count: u32,
    last: Option<f64>,
}

struct Demo {
    config_path: PathBuf,
    public_dir: PathBuf,
    public_url: String,
    public_given: bool,
    port: String,
    secret: Vec<u8>,
    state: Mutex<State>,
}

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Outgoing {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Outcome {
    outgoing: Outgoing,
    watch: Option<(Grant, Person)>,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (public, given) = public_url(&args);
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let port_n: u16 = match port.parse() {
        Ok(value) if value > 0 => value,
        _ => {
            eprintln!("PORT must be a TCP port");
            std::process::exit(1);
        }
    };
    let demo = Arc::new(Demo::new(public, given, port));
    let listener = match TcpListener::bind(("0.0.0.0", port_n)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    println!("gnap-caep-risc demo on port {port_n}, configuration {}", demo.config_path.display());
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let demo = Arc::clone(&demo);
        thread::spawn(move || {
            if let Err(err) = serve(&demo, stream) {
                eprintln!("{err}");
            }
        });
    }
}

fn public_url(argv: &[String]) -> (String, bool) {
    let env = std::env::var("PUBLIC_URL").unwrap_or_default();
    let mut given = !env.is_empty();
    let mut public = env.trim_end_matches('/').to_string();
    let mut index = 0;
    while index < argv.len() {
        if argv[index] == "--public-url" {
            index += 1;
            public = if index < argv.len() { argv[index].trim_end_matches('/').to_string() } else { String::new() };
            given = true;
        }
        index += 1;
    }
    (public, given)
}

impl Demo {
    fn new(public: String, given: bool, port: String) -> Self {
        let mut secret = vec![0u8; 32];
        if let Ok(env) = std::env::var("SESSION_SECRET") {
            if !env.is_empty() {
                secret = env.into_bytes();
            } else {
                rand::thread_rng().fill_bytes(&mut secret);
            }
        } else {
            rand::thread_rng().fill_bytes(&mut secret);
        }
        let config_path = std::env::var("GNAP_CONFIG").unwrap_or_else(|_| "demo/gnap.json".into());
        let config_path = PathBuf::from(config_path);
        let public_dir = config_path.parent().unwrap_or_else(|| Path::new(".")).join("public");
        Self {
            config_path,
            public_dir,
            public_url: public,
            public_given: given,
            port,
            secret,
            state: Mutex::new(State { client: None, client_err: String::new(), sessions: HashMap::new(), receiver: None, receiver_state: "not started (nobody has signed in)".into(), events: Vec::new(), event_seq: 0, latest: None, rotations: HashMap::new() }),
        }
    }

    fn read_raw(&self) -> Result<Value, String> {
        let text = std::fs::read_to_string(&self.config_path).map_err(|err| err.to_string())?;
        let mut doc: Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
        let display_uri = doc.get("display").and_then(|item| item.get("uri")).and_then(|item| item.as_str()).unwrap_or("").to_string();
        let finish = doc.get("finishUri").and_then(|item| item.as_str()).unwrap_or("").to_string();
        let moved = redirects_for(&finish, &display_uri, &self.public_url, self.public_given, &self.port);
        let Some(obj) = doc.as_object_mut() else { return Err("the configuration must be a JSON object".into()) };
        if !moved.finish.is_empty() {
            obj.insert("finishUri".into(), Value::String(moved.finish));
        }
        if !display_uri.is_empty() && !moved.display.is_empty() {
            if let Some(display) = obj.get_mut("display").and_then(|item| item.as_object_mut()) {
                display.insert("uri".into(), Value::String(moved.display));
            }
        }
        Ok(doc)
    }

    fn ensure_client(&self) -> Result<Arc<Client>, String> {
        if let Some(client) = self.state.lock().unwrap().client.clone() {
            return Ok(client);
        }
        let doc = match self.read_raw() {
            Ok(doc) => doc,
            Err(err) => {
                self.state.lock().unwrap().client_err = err.clone();
                return Err(err);
            }
        };
        let parent = self.config_path.parent().unwrap_or_else(|| Path::new("."));
        let cfg = match Client::resolve(&doc, parent) {
            Ok(cfg) => cfg,
            Err(err) => {
                let msg = format!("{}: {}", err.code, err.message);
                self.state.lock().unwrap().client_err = msg.clone();
                return Err(msg);
            }
        };
        // `create` starts the embedded PEP when there is a `pep` section.
        let client = match Client::create(cfg) {
            Ok(client) => Arc::new(client),
            Err(err) => {
                let msg = format!("{}: {}", err.code, err.message);
                self.state.lock().unwrap().client_err = msg.clone();
                return Err(msg);
            }
        };
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = &state.client {
            return Ok(existing.clone());
        }
        state.client = Some(Arc::clone(&client));
        state.client_err.clear();
        Ok(client)
    }

    fn try_client(&self) -> Option<Arc<Client>> {
        self.ensure_client().ok()
    }

    fn dispatch(self: &Arc<Self>, req: &Request) -> Outcome {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/healthz") => plain(200, "ok"),
            ("GET", "/styles.css") => self.static_file("styles.css", "text/css; charset=utf-8"),
            ("GET", "/app.js") => self.static_file("app.js", "text/javascript; charset=utf-8"),
            ("GET", "/pep.js") => self.static_file("pep.js", "text/javascript; charset=utf-8"),
            ("GET", "/panes.js") => self.static_file("panes.js", "text/javascript; charset=utf-8"),
            ("GET", "/menu.js") => self.static_file("menu.js", "text/javascript; charset=utf-8"),
            ("GET", "/api/signals") => self.signals_api(req),
            // No Server-Sent Events here: 204 tells app.js's EventSource to
            // give up, and it polls /api/signals every 3 s instead.
            ("GET", "/events") => reply(204, vec![("cache-control".into(), "no-store".into())], Vec::new()),
            ("POST", "/signals/verify") => self.verify_signals(req),
            ("POST", "/session/rotate") => self.session_rotate(req),
            ("POST", "/login/another") => self.login_another(req),
            ("GET", "/pep-status") => self.pep_status_page(req, false),
            ("GET", "/pep-status.html") => self.pep_status_page(req, true),
            ("GET", "/") => self.home(req),
            ("GET", "/live-status") => self.live_status(req),
            ("GET", "/login") => self.login(),
            ("GET", "/callback") => self.callback(req),
            ("POST", "/logout") => self.logout(req),
            ("POST", "/gnap/push") => self.push(req),
            #[cfg(feature = "pep")]
            (_, "/attribute-protected") => self.attribute_protected(req),
            #[cfg(feature = "pep")]
            (method, path) if path.strip_prefix("/orders/").is_some_and(|id| !id.is_empty() && !id.contains('/')) => {
                let id = path["/orders/".len()..].to_string();
                self.order(req, method, &id)
            }
            _ => self.html(404, "Not found", "<h1>Not found</h1>", Vec::new()),
        }
    }

    /// A route the embedded PEP protects (the `pep` feature, iya-sts#1206):
    /// the signed-in person's access to one order, decided by the `pep`
    /// section's PEP from the grant's subject. A GET is `read` and anything
    /// else `write`. No sign-in is 401, a Deny 403, and any other PEP
    /// failure 403 too (no decision, or no GNAP client to ask): an
    /// enforcement point that cannot say yes says no, and the page says
    /// which. Never served.
    #[cfg(feature = "pep")]
    fn order(&self, req: &Request, method: &str, id: &str) -> Outcome {
        use gnap_caep_risc::pep::{Access, Decision};
        let Some(session) = self.session(req) else {
            return self.sign_in_first();
        };
        let Some(client) = self.try_client() else {
            return self.not_configured(&session);
        };
        let action = if method == "GET" { "read" } else { "write" };
        let decision = client.decide_grant(&session.grant, &Access::new(action, "order", id));
        // 200 for a Permit, 403 for anything else: the PEP's own answer.
        let status = decision.http_status();
        let (title, body) = match decision {
            Decision::Permit { obligations, .. } => {
                let note = if obligations.is_empty() { String::new() } else { format!("<p><small>{} obligation(s) to discharge.</small></p>", obligations.len()) };
                ("Order", format!("<h1>Order {}</h1><p>The PEP permitted <code>{action}</code>.</p>{note}", escape(id)))
            }
            Decision::Deny { why } => ("Forbidden", format!("<h1>Not allowed</h1><p>The PEP denied <code>{action}</code> on order {}: {}</p>", escape(id), escape(&why))),
            Decision::Unavailable { why } => ("Forbidden", format!("<h1>No decision</h1><p>The PEP could not decide: {}</p>", escape(&why))),
        };
        self.html_for(status, title, &body, Vec::new(), Some(&session))
    }

    /// `/attribute-protected`: decided by the embedded PEP against the demo
    /// application's own (fine-grained authorization) policy, which permits
    /// `read` on it to a person whose directory attribute attr1 is abc123.
    /// The value is in neither the grant nor its ID token assertion: the PEP
    /// asks iya-sts's PIP for it (`POST /xacml/pip`), in `local` mode as in
    /// `central`. 401 without a sign-in, 200 on a Permit, 403 on a Deny and
    /// on any other PEP failure (no decision, or no GNAP client to ask), the
    /// page saying which.
    #[cfg(feature = "pep")]
    fn attribute_protected(&self, req: &Request) -> Outcome {
        use gnap_caep_risc::pep::{Access, Decision};
        let Some(session) = self.session(req) else {
            return self.sign_in_first();
        };
        let Some(client) = self.try_client() else {
            return self.not_configured(&session);
        };
        let what = "<p><small>The demo application's policy permits <code>read</code> on <code>attribute-protected</code> when your directory attribute <code>attr1</code> is <code>abc123</code>. The PEP asked iya-sts's PIP for it: it is not in your grant or its ID token assertion.</small></p>";
        let decision = client.decide_grant(&session.grant, &Access::new("read", "attribute-protected", "attr1"));
        // 200 for a Permit, 403 for anything else: the PEP's own answer.
        let status = decision.http_status();
        let (title, body) = match decision {
            Decision::Permit { .. } => ("Attribute-protected", format!("<h1>Allowed</h1><p class=\"notice\">The PEP permitted it: your <code>attr1</code> is <code>abc123</code>.</p>{what}")),
            Decision::Deny { why } => ("Forbidden", format!("<h1>Not allowed</h1><p class=\"problem\">The PEP denied it: {}</p>{what}", escape(&why))),
            Decision::Unavailable { why } => ("Forbidden", format!("<h1>No decision</h1><p class=\"problem\">The PEP could not decide: {}</p>{what}", escape(&why))),
        };
        self.html_for(status, title, &body, Vec::new(), Some(&session))
    }

    #[cfg(feature = "pep")]
    fn sign_in_first(&self) -> Outcome {
        self.html(401, "Sign in", "<h1>Sign in first</h1><p><a class=\"button\" href=\"/login\">Sign in with GNAP</a></p>", Vec::new())
    }

    /// A PEP-protected page with no GNAP client to ask: a PEP failure, so 403.
    #[cfg(feature = "pep")]
    fn not_configured(&self, session: &SessionRecord) -> Outcome {
        self.html_for(403, "Forbidden", "<h1>Not allowed</h1><p class=\"problem\">No decision could be asked for: the GNAP client is not configured.</p>", Vec::new(), Some(session))
    }

    fn static_file(&self, name: &str, content_type: &str) -> Outcome {
        match std::fs::read(self.public_dir.join(name)) {
            Ok(raw) => reply(200, vec![("content-type".into(), content_type.into()), ("cache-control".into(), "max-age=300".into())], raw),
            Err(_) => self.html(404, "Not found", "<h1>Not found</h1>", Vec::new()),
        }
    }

    fn home(&self, req: &Request) -> Outcome {
        let client = self.try_client();
        if let (Some(sid), Some(session)) = (self.session_id(req), self.session(req)) {
            let notice = match req.query.get("done").map(String::as_str) {
                Some("rotated") => "The access token was rotated.",
                Some("rotate-refused") => "The rotation was refused; see the Token cache.",
                _ => "",
            };
            let tab = match req.query.get("tab").map(String::as_str) {
                Some("pep") => "pep",
                Some("events") => "events",
                _ => "session",
            };
            // The session's grant, rotated first when its access token is about to expire.
            let (session, problem) = match client.as_ref() {
                Some(client) => self.fresh_session(client, &sid, session),
                None => (session, None),
            };
            let (events, stream, rotations) = {
                let state = self.state.lock().unwrap();
                (state.events.clone(), state.receiver_state.clone(), state.rotations.get(&sid).cloned().unwrap_or_default())
            };
            let last_id = events.last().map(|e| e.id).unwrap_or(0);
            // Every tab's blocks are collapsible panes; one toggle opens or
            // closes every pane on the tab (panes.js shows it).
            let toggle = "<p class=\"pane-tools\"><button type=\"button\" class=\"secondary small\" id=\"panes-toggle\" hidden>Collapse all</button></p>";
            let content = match tab {
                "pep" => format!("{toggle}<div id=\"pep-panel\" aria-live=\"polite\">{}</div><script src=\"/pep.js\" defer></script>", pep_fragment(client.as_deref())),
                "events" => {
                    let notice = match req.query.get("verify").map(String::as_str) {
                        Some("sent") => "A verification event was requested; it appears below when the transmitter sends it.",
                        Some("refused") => "The transmitter refused the verification request.",
                        _ => "",
                    };
                    format!("{toggle}{}", events_panel(&events, &stream, notice))
                }
                _ => match client.as_deref() {
                    Some(client) => format!("{toggle}{}", session_panes(client, &session, problem, &rotations, &stream, notice)),
                    None => "<p class=\"problem\">The GNAP client is not configured.</p>".to_string(),
                },
            };
            let tab_link = |id: &str, href: &str, label: &str| {
                let on = id == tab;
                format!("<a class=\"page-tab\" role=\"tab\" href=\"{href}\" aria-selected=\"{on}\"{}>{label}</a>", if on { " aria-current=\"page\"" } else { "" })
            };
            let count = if events.is_empty() { String::new() } else { events.len().to_string() };
            let body = format!(
                "<h1>Signed in as {}</h1><nav class=\"page-tabs\" role=\"tablist\" aria-label=\"Sections\">{}{}{}</nav><p id=\"signal-banner\" class=\"problem\" hidden></p><p id=\"signal-toast\" class=\"notice\" hidden></p><div role=\"tabpanel\" id=\"panel\" data-base=\"\" data-tab=\"{tab}\" data-last-id=\"{last_id}\">{content}</div><script src=\"/app.js\" defer></script><script src=\"/panes.js\" defer></script>",
                escape(&record_name(&session)),
                tab_link("session", "/", "Session"),
                tab_link("events", "/?tab=events", &format!("CAEP &amp; RISC events <span class=\"count\" id=\"signal-count\">{count}</span>")),
                tab_link("pep", "/?tab=pep", "Policy enforcement"),
            );
            return self.html_for(200, "Signed in", &body, Vec::new(), Some(&session));
        }
        let another = if req.query.get("another").map(String::as_str) == Some("1") {
            "<p class=\"notice\">You are signed out of this demo. Sign in again to use another account: iya-sts asks who you are unless it still holds a sign-on session for you, so sign out at iya-sts first to choose someone else.</p>"
        } else {
            ""
        };
        if client.is_none() {
            let msg = {
                let state = self.state.lock().unwrap();
                if state.client_err.is_empty() { "the key could not be read".into() } else { state.client_err.clone() }
            };
            let body = format!("<h1>GNAP CAEP RISC demo</h1><p class=\"problem\">The GNAP client is not configured yet: {}. Generate the key at the privateKey path, then run scripts/configure_iya_sts.py.</p>", escape(&msg));
            return self.html(200, "GNAP demo", &body, Vec::new());
        }
        let body = format!("<h1>GNAP CAEP RISC demo</h1>{another}<p>This application is a GNAP client instance. It asks iya-sts for a grant, sends the browser to the interaction, and takes the access token on the back channel, every request signed with the client's own key.</p><p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with GNAP</a></p>");
        self.html(200, "GNAP demo", &body, Vec::new())
    }

    /// The session's grant with an access token that is not about to
    /// expire: `ensure_fresh` rotates it (through the token management URI)
    /// when 60 s or less are left, and the rotated grant replaces the
    /// session's. Answers the session as it now is, and why its token is
    /// not valid when it is not.
    fn fresh_session(&self, client: &Client, sid: &str, session: SessionRecord) -> (SessionRecord, Option<String>) {
        let expired = |grant: &Grant| grant.expires_at.is_some_and(|at| at <= now_secs() * 1000.0);
        if !session.grant.expires_at.is_some_and(|at| at - now_secs() * 1000.0 <= 60_000.0) {
            return (session, None);
        }
        if session.grant.manage.is_none() {
            let why = if expired(&session.grant) { Some("it expired, and the grant has no token management URI to rotate it".into()) } else { None };
            return (session, why);
        }
        match client.ensure_fresh(&session.grant) {
            Ok(grant) => (self.replace_grant(sid, session, grant), None),
            Err(err) => {
                let why = format!("the rotation was refused: {err}");
                (session, Some(why))
            }
        }
    }

    /// Puts a rotated grant in the session (and, when it was the one the
    /// receiver authorizes its calls with, there too), and counts it.
    fn replace_grant(&self, sid: &str, mut session: SessionRecord, grant: Grant) -> SessionRecord {
        let mut state = self.state.lock().unwrap();
        if state.latest.as_ref().is_some_and(|latest| latest.access_token == session.grant.access_token) {
            state.latest = Some(grant.clone());
        }
        session.grant = grant;
        state.sessions.insert(sid.to_string(), session.clone());
        let entry = state.rotations.entry(sid.to_string()).or_default();
        entry.count += 1;
        entry.last = Some(now_secs());
        session
    }

    /// `POST /session/rotate`: rotates the access token now, whatever is
    /// left of it, through the token management URI.
    fn session_rotate(&self, req: &Request) -> Outcome {
        let (Some(sid), Some(session), Some(client)) = (self.session_id(req), self.session(req), self.try_client()) else {
            return see_other("/");
        };
        if session.grant.manage.is_none() {
            return see_other("/?done=rotate-refused#token-card");
        }
        match client.rotate(&session.grant) {
            Ok(grant) => {
                self.replace_grant(&sid, session, grant);
                see_other("/?done=rotated#token-card")
            }
            Err(err) => {
                println!("rotate: {err}");
                see_other("/?done=rotate-refused#token-card")
            }
        }
    }

    /// `POST /login/another`: "Sign in with another account". GNAP has no
    /// prompt to make iya-sts ask again, so this ends the sign-in here (the
    /// grant revoked, as Sign out does) and goes back to the sign-in page,
    /// which says how to choose another account.
    fn login_another(&self, req: &Request) -> Outcome {
        self.end_session(req);
        reply(
            303,
            vec![
                ("location".into(), "/?another=1".into()),
                ("cache-control".into(), "no-store".into()),
                ("set-cookie".into(), "gsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax".into()),
            ],
            Vec::new(),
        )
    }

    /// `GET /api/signals?after=<id>`: the events after the last one the page
    /// shows, and the stream's state. 401 once the session is gone, which
    /// `app.js` reads as signed out.
    fn signals_api(&self, req: &Request) -> Outcome {
        let json_reply = |status: u16, body: Value| reply(status, vec![("content-type".into(), "application/json".into()), ("cache-control".into(), "no-store".into())], body.to_string().into_bytes());
        if self.session(req).is_none() {
            return json_reply(401, serde_json::json!({"signedIn": false}));
        }
        let after = req.query.get("after").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let state = self.state.lock().unwrap();
        let events: Vec<Value> = state.events.iter().filter(|e| e.id > after).map(event_json).collect();
        json_reply(200, serde_json::json!({"events": events, "streamStatus": {"status": state.receiver_state, "at": utc(now_secs())}}))
    }

    /// `POST /signals/verify`: asks the transmitter for a verification event
    /// on the stream. JSON for `app.js`, a redirect back to the tab without it.
    fn verify_signals(&self, req: &Request) -> Outcome {
        if self.session(req).is_none() {
            return see_other("/");
        }
        let (receiver, seq) = {
            let state = self.state.lock().unwrap();
            (state.receiver.clone(), state.event_seq)
        };
        let outcome = match receiver.map(|r| r.verify(Some(&format!("demo-{}", seq + 1)))) {
            Some(Ok(())) => "sent",
            Some(Err(err)) => {
                println!("ssf: verification request refused: {err}");
                "refused"
            }
            None => "refused",
        };
        let wants_json = req.headers.iter().any(|(k, v)| k == "accept" && v.contains("application/json"));
        if wants_json {
            reply(200, vec![("content-type".into(), "application/json".into())], serde_json::json!({"outcome": outcome}).to_string().into_bytes())
        } else {
            see_other(&format!("/?tab=events&verify={outcome}"))
        }
    }

    /// `GET /pep-status` (JSON) and `/pep-status.html` (the Policy
    /// enforcement tab's fragment): what the embedded PEP holds and has done.
    /// For a signed-in browser only, like the page that shows it. Nothing in
    /// it is secret: counts, times, tokens that name policy versions, and the
    /// PEP key's public thumbprint.
    fn pep_status_page(&self, req: &Request, html: bool) -> Outcome {
        if self.session(req).is_none() {
            return plain(401, "sign in first");
        }
        let client = self.try_client();
        let no_store = ("cache-control".to_string(), "no-store".to_string());
        if html {
            reply(200, vec![("content-type".into(), "text/html; charset=utf-8".into()), no_store], pep_fragment(client.as_deref()).into_bytes())
        } else {
            reply(200, vec![("content-type".into(), "application/json".into()), no_store], pep_json(client.as_deref()).to_string().into_bytes())
        }
    }

    /// The sign-in and the Shared Signals events, for scripts/live_iya_sts.py. It carries no token
    /// and no assertion: only whether this browser is signed in, who as, the receiver's state, and
    /// the type and jti of each event received.
    fn live_status(&self, req: &Request) -> Outcome {
        let subject = self.session(req).and_then(|session| session.person).map(|person| display_name(&person));
        let (receiver, events) = {
            let state = self.state.lock().unwrap();
            let events: Vec<Value> = state.events.iter().map(|e| serde_json::json!({"type": e.event_type, "jti": e.jti})).collect();
            (state.receiver_state.clone(), events)
        };
        #[allow(unused_mut)]
        let mut body = serde_json::json!({
            "signedIn": subject.is_some(),
            "subject": subject,
            "receiver": receiver,
            "events": events,
        });
        // The embedded PEP's status, which holds no secret: its `syncToken`
        // is the version of the policy held, not a credential.
        #[cfg(feature = "pep")]
        if let Some(pep) = self.try_client().as_ref().and_then(|client| client.pep().cloned()) {
            let s = pep.status();
            body["pep"] = serde_json::json!({
                "name": s.name,
                "mode": if s.mode == gnap_caep_risc::pep::Mode::Local { "local" } else { "central" },
                "application": s.application,
                "registered": s.registered,
                "running": s.running,
                "holdsPolicy": s.holds_policy,
                "policyCount": s.policy_count,
                "syncToken": s.sync_token,
                "eventsReceived": s.events_received,
                "eventStream": s.event_stream.as_str(),
                "lastError": s.last_error,
            });
        }
        reply(200, vec![("content-type".into(), "application/json".into()), ("cache-control".into(), "no-store".into())], serde_json::to_vec(&body).unwrap_or_default())
    }

    fn remember_event(&self, event: &SignalEvent) {
        let mut state = self.state.lock().unwrap();
        state.event_seq += 1;
        let live = LiveEvent::of(state.event_seq, event);
        state.events.push(live);
        let over = state.events.len().saturating_sub(MAX_EVENTS);
        state.events.drain(..over);
        if event.event_type != Events::SESSION_REVOKED || state.sessions.is_empty() {
            return;
        }
        // on_end removes sessions by the tracked local id. This demo tracks the grant id, or the
        // subject, and the browser cookie names a different id, so session-revoked can arrive while
        // that one session is still signed in. End it.
        println!("ssf: session-revoked left the cookie session signed in; the receiver tracks the grant id, not that cookie, so ending this demo's one session");
        state.sessions.clear();
    }

    fn login(self: &Arc<Self>) -> Outcome {
        let client = match self.ensure_client() {
            Ok(client) => client,
            Err(err) => return self.fail_page(&err, Vec::new()),
        };
        let started = match client.request_grant() {
            Ok(started) => started,
            Err(err) => return self.fail_page(&err.to_string(), Vec::new()),
        };
        if let Some(grant) = started.grant {
            return reply_only(self.place(&grant, None));
        }
        let Some(pending) = started.pending else {
            return self.fail_page("the grant response has neither an interaction nor an access token", Vec::new());
        };
        let sealed = self.seal(&serde_json::json!({"ids": [pending.id]}));
        let secure = if client.config.finish_uri.as_deref().unwrap_or("").starts_with("https:") { "; Secure" } else { "" };
        let cookie = format!("gpending={sealed}; Path=/callback; Max-Age=600; HttpOnly; SameSite=Lax{secure}");
        reply(
            302,
            vec![
                ("location".into(), started.redirect_url.unwrap_or_default()),
                ("set-cookie".into(), cookie),
                ("cache-control".into(), "no-store".into()),
            ],
            Vec::new(),
        )
    }

    fn callback(self: &Arc<Self>, req: &Request) -> Outcome {
        let pending = self.unseal(cookie_value(&req.headers, "gpending"));
        let ids = pending.as_ref().map(ids_of).unwrap_or_default();
        let clear = "gpending=; Path=/callback; Max-Age=0; HttpOnly; SameSite=Lax".to_string();
        let client = match self.ensure_client() {
            Ok(client) => client,
            Err(err) => return self.fail_page(&err, vec![("set-cookie".into(), clear)]),
        };
        let done = match client.finish_redirect(req.query.clone(), &ids) {
            Ok(done) => done,
            Err(err) => {
                println!("sign-in refused: {err}");
                return self.fail_page(&err.to_string(), vec![("set-cookie".into(), clear)]);
            }
        };
        let Some(person) = done.grant.subject.clone() else {
            println!("sign-in refused: the grant has no subject");
            return self.fail_page("the grant has no subject", vec![("set-cookie".into(), clear)]);
        };
        Outcome { outgoing: self.place(&done.grant, Some(clear)), watch: Some((done.grant, person)) }
    }

    fn place(&self, grant: &Grant, extra: Option<String>) -> Outgoing {
        let local = random_token();
        self.state.lock().unwrap().sessions.insert(local.clone(), SessionRecord { person: grant.subject.clone(), grant: grant.clone() });
        let mut cookies = vec![format!("gsid={}; Path=/; HttpOnly; SameSite=Lax", self.seal(&serde_json::json!({"id": local})))];
        if let Some(extra) = extra {
            cookies.push(extra);
        }
        let mut headers = vec![("location".into(), "/".into()), ("cache-control".into(), "no-store".into())];
        for cookie in cookies {
            headers.push(("set-cookie".into(), cookie));
        }
        Outgoing { status: 303, headers, body: Vec::new() }
    }

    fn logout(&self, req: &Request) -> Outcome {
        self.end_session(req);
        reply(
            303,
            vec![
                ("location".into(), "/".into()),
                ("cache-control".into(), "no-store".into()),
                ("set-cookie".into(), "gsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax".into()),
            ],
            Vec::new(),
        )
    }

    /// Ends this browser's sign-in: the local session goes, the receiver
    /// stops tracking its grant, and the grant is revoked at iya-sts.
    fn end_session(&self, req: &Request) {
        let Some(opened) = self.unseal(cookie_value(&req.headers, "gsid")) else { return };
        let Some(id) = opened.get("id").and_then(|item| item.as_str()) else { return };
        let (session, receiver) = {
            let mut state = self.state.lock().unwrap();
            let session = state.sessions.remove(id);
            state.rotations.remove(id);
            let receiver = state.receiver.clone();
            (session, receiver)
        };
        let Some(session) = session else { return };
        if let Some(receiver) = receiver {
            if let Some(grant_id) = session.grant.grant_id.as_deref() {
                if !grant_id.is_empty() {
                    receiver.untrack(grant_id);
                }
            }
        }
        if let Ok(client) = self.ensure_client() {
            if let Err(err) = client.revoke(&session.grant) {
                println!("revoke: {err}");
            }
        }
    }

    fn push(self: &Arc<Self>, req: &Request) -> Outcome {
        let client = match self.ensure_client() {
            Ok(client) => client,
            Err(err) => return json_err(&err),
        };
        let body = if req.body.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(body) => body,
                Err(err) => return json_err(&err.to_string()),
            }
        };
        let done = match client.finish_push(&body) {
            Ok(done) => done,
            Err(err) => return json_err(&err.to_string()),
        };
        let watch = done.grant.subject.clone().map(|person| (done.grant, person));
        Outcome { outgoing: Outgoing { status: 204, headers: vec![("cache-control".into(), "no-store".into())], body: Vec::new() }, watch }
    }

    fn signals_wanted(&self) -> Option<(String, i64)> {
        let text = std::fs::read_to_string(&self.config_path).ok()?;
        let doc: Value = serde_json::from_str(&text).ok()?;
        if doc.get("signals") == Some(&Value::Bool(false)) {
            return None;
        }
        let ssf = doc.get("ssf")?.as_object()?;
        let transmitter = ssf.get("transmitter").and_then(|item| item.as_str()).unwrap_or("").trim().to_string();
        if transmitter.is_empty() {
            return None;
        }
        let interval = ssf
            .get("pollIntervalMs")
            .and_then(|item| item.as_i64().or_else(|| item.as_f64().map(|value| value as i64)))
            .filter(|value| *value != 0)
            .unwrap_or(5000);
        Some((transmitter, interval))
    }

    fn watch(self: &Arc<Self>, grant: &Grant, person: &Person) {
        {
            let mut state = self.state.lock().unwrap();
            state.latest = Some(grant.clone());
            if state.receiver.is_some() {
                return;
            }
        }
        let Some((transmitter, interval)) = self.signals_wanted() else {
            self.state.lock().unwrap().receiver_state = "not configured (signals are off, or no ssf.transmitter)".into();
            return;
        };
        let Ok(client) = self.ensure_client() else { return };
        let demo_end = Arc::clone(self);
        let on_end: Arc<EndFn> = Arc::new(move |ids, _event| {
            let mut state = demo_end.state.lock().unwrap();
            for id in ids {
                state.sessions.remove(id);
            }
        });
        let demo_headers = Arc::clone(self);
        let mut opt = ReceiverOpt::new(transmitter.clone(), on_end);
        opt.set_headers(move |method, url, body| {
            let latest = demo_headers.state.lock().unwrap().latest.clone();
            let Some(latest) = latest else { return Vec::new() };
            let Ok(current) = demo_headers.ensure_client() else { return Vec::new() };
            match current.authorization_headers(&latest, method, url, body) {
                Ok(map) => map.into_iter().collect(),
                Err(_) => Vec::new(),
            }
        });
        opt.tls = client.tls();
        opt.poll_interval_ms = interval;
        #[cfg(feature = "pep")]
        {
            opt.pep = client.pep().cloned();
        }
        let receiver = match SignalsReceiver::new(opt) {
            Ok(receiver) => receiver,
            Err(err) => {
                println!("ssf: not started: {err}");
                self.state.lock().unwrap().receiver_state = format!("not running: {err}");
                return;
            }
        };
        let demo_events = Arc::clone(self);
        receiver.on("*", Arc::new(move |event: &SignalEvent| demo_events.remember_event(event)));
        if let Err(err) = receiver.start() {
            println!("ssf: not started: {err}");
            self.state.lock().unwrap().receiver_state = format!("not running: {err}");
            return;
        }
        let stream_id = receiver.stream().and_then(|stream| stream.get("stream_id").and_then(|item| item.as_str()).map(|id| id.to_string())).unwrap_or_default();
        let local = match grant.grant_id.as_deref() {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => person.sub.clone(),
        };
        receiver.track(TrackedSession {
            local_id: local,
            person: Some(person.sub.clone()),
            email: person.email.clone(),
            idp_session: person.sid.clone(),
            expires_at: grant.expires_at,
        });
        let mut state = self.state.lock().unwrap();
        state.receiver_state = format!("polling stream {stream_id} at {transmitter}");
        state.receiver = Some(receiver);
    }

    fn session(&self, req: &Request) -> Option<SessionRecord> {
        let id = self.session_id(req)?;
        self.state.lock().unwrap().sessions.get(&id).cloned()
    }

    /// The local session id the browser's cookie names, when that session exists.
    fn session_id(&self, req: &Request) -> Option<String> {
        let opened = self.unseal(cookie_value(&req.headers, "gsid"))?;
        let id = opened.get("id").and_then(|item| item.as_str())?.to_string();
        self.state.lock().unwrap().sessions.contains_key(&id).then_some(id)
    }

    fn seal(&self, payload: &Value) -> String {
        let raw = serde_json::to_vec(payload).unwrap_or_default();
        let encoded = URL_SAFE_NO_PAD.encode(raw);
        let mac = hmac_sha256(&self.secret, encoded.as_bytes());
        format!("{encoded}.{}", hex_encode(&mac))
    }

    fn unseal(&self, token: &str) -> Option<Value> {
        let dot = token.rfind('.')?;
        if dot == 0 {
            return None;
        }
        let raw = &token[..dot];
        let mac_text = &token[dot + 1..];
        let mac = hmac_sha256(&self.secret, raw.as_bytes());
        if !constant_eq(&hex_encode(&mac), mac_text) {
            return None;
        }
        let decoded = URL_SAFE_NO_PAD.decode(raw).ok()?;
        serde_json::from_slice(&decoded).ok()
    }

    fn html(&self, status: u16, title: &str, body: &str, headers: Vec<(String, String)>) -> Outcome {
        self.html_for(status, title, body, headers, None)
    }

    /// A page, with the demo's links and the user menu in the top bar when
    /// someone is signed in.
    fn html_for(&self, status: u16, title: &str, body: &str, headers: Vec<(String, String)>, who: Option<&SessionRecord>) -> Outcome {
        let page = page_for(title, body, who);
        let mut headers = headers;
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-type")) {
            headers.push(("content-type".into(), "text/html; charset=utf-8".into()));
        }
        // Scripts and styles from this origin only; pep.js fetches the tab's
        // fragment from it, which `connect-src 'self'` allows.
        headers.push(("content-security-policy".into(), CSP.into()));
        // A signed-in page names the person; no page is kept by a cache.
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("cache-control")) {
            headers.push(("cache-control".into(), "no-store".into()));
        }
        reply(status, headers, page.into_bytes())
    }

    fn fail_page(&self, err: &str, headers: Vec<(String, String)>) -> Outcome {
        let body = format!("<h1>Sign-in failed</h1><p>{}</p><p><a href=\"/\">Start again</a></p>", escape(err));
        self.html(400, "Sign-in failed", &body, headers)
    }
}

fn serve(demo: &Arc<Demo>, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let req = match read_request(&mut stream) {
        Ok(req) => req,
        Err(_) => return Ok(()),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| demo.dispatch(&req)));
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(_) => demo.html(500, "Error", "<h1>Something went wrong</h1><p><a href=\"/\">Home</a></p>", Vec::new()),
    };
    write_response(&mut stream, &outcome.outgoing)?;
    if let Some((grant, person)) = outcome.watch {
        demo.watch(&grant, &person);
    }
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_split(&buf) {
            break pos;
        }
        if buf.len() > 65_536 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the request header is too large"));
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the request ended"));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let length = headers.iter().find(|(name, _)| name == "content-length").and_then(|(_, value)| value.parse::<usize>().ok()).unwrap_or(0);
    if length > 2 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the request body is too large"));
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(length);
    let (path, query) = split_target(&target);
    Ok(Request { method, path, query, headers, body })
}

fn find_split(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let joined = if target.starts_with('/') { format!("http://demo.local{target}") } else { target.to_string() };
    let Ok(url) = url::Url::parse(&joined) else { return (target.to_string(), HashMap::new()) };
    let mut query = HashMap::new();
    for (key, value) in url.query_pairs() {
        query.entry(key.into_owned()).or_insert_with(|| value.into_owned());
    }
    (url.path().to_string(), query)
}

fn write_response(stream: &mut TcpStream, outgoing: &Outgoing) -> std::io::Result<()> {
    let reason = match outgoing.status {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut head = format!("HTTP/1.1 {} {reason}\r\n", outgoing.status);
    for (name, value) in &outgoing.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", outgoing.body.len()));
    stream.write_all(head.as_bytes())?;
    stream.write_all(&outgoing.body)?;
    stream.flush()
}

const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[cfg(feature = "pep")]
fn pep_json(client: Option<&Client>) -> Value {
    use serde_json::json;
    let Some(pep) = client.and_then(|client| client.pep()) else {
        return json!({"enabled": false, "why": "no pep section is configured"});
    };
    let s = pep.status();
    let ms = |d: Option<Duration>| d.map(|d| d.as_millis() as u64);
    let mode = if s.mode == gnap_caep_risc::pep::Mode::Local { "local" } else { "central" };
    json!({
        "enabled": true,
        "name": s.name, "mode": mode, "application": s.application, "pdpUrl": s.pdp_url,
        "protocolVersion": s.protocol_version, "registered": s.registered, "running": s.running,
        "eventStream": s.event_stream.as_str(), "keyThumbprint": s.key_thumbprint, "problems": s.last_error,
        "policy": {
            "held": s.holds_policy, "count": s.policy_count, "syncToken": s.sync_token,
            "catalogueToken": s.catalogue_token, "catalogueSubjectClaims": s.catalogue_subject_properties,
            "sinceUpdateMs": ms(s.since_policy_update), "sinceLastPullMs": ms(s.since_last_pull),
            "untilNextPullMs": ms(s.until_next_pull), "pulls": s.pulls, "pullsChanged": s.pulls_changed,
            "pullFailures": s.pull_failures, "eventsReceived": s.events_received, "eventsIgnored": s.events_ignored,
            "sinceLastEventMs": ms(s.since_last_event),
        },
        "decisions": {
            "total": s.decisions, "allowed": s.allowed, "denied": s.refused, "unavailable": s.unavailable,
            "undischargeable": s.undischargeable, "meanMicros": s.mean_decision_micros, "maxMicros": s.max_decision_micros,
            "permitCacheEntries": s.permit_cache_entries, "permitCacheHits": s.permit_cache_hits,
        },
        "controlPlane": {
            "uptimeMs": ms(s.uptime), "registrations": s.registrations, "heartbeats": s.heartbeats,
            "heartbeatFailures": s.heartbeat_failures, "sinceLastHeartbeatMs": ms(s.since_last_heartbeat),
            "untilNextHeartbeatMs": ms(s.until_next_heartbeat), "recordsQueued": s.records_queued,
            "recordsShipped": s.records_shipped, "recordsDropped": s.records_dropped,
        },
    })
}

#[cfg(not(feature = "pep"))]
fn pep_json(_client: Option<&Client>) -> Value {
    serde_json::json!({"enabled": false, "why": "this demo was built without the pep feature"})
}

/// A duration as a person reads it: `ago` for one past, else one to come.
fn human(d: Option<Duration>, ago: bool) -> String {
    let Some(d) = d else { return "—".into() };
    let s = d.as_secs();
    if s == 0 {
        return if ago { "just now".into() } else { "now".into() };
    }
    let text = if s < 120 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} h {} min", s / 3600, s % 3600 / 60)
    };
    if ago { format!("{text} ago") } else { format!("in {text}") }
}

/// The Policy enforcement tab's content: four collapsible panes drawn by the
/// server, everything escaped, and fetched again every two seconds by
/// `pep.js`, which keeps a pane the person closed closed (by its stable id).
fn pep_fragment(client: Option<&Client>) -> String {
    let v = pep_json(client);
    if v["enabled"] != Value::Bool(true) {
        return pane("pep-none", "No embedded PEP", "", &format!(
            "<p class=\"notice\">No embedded PEP: {}. Add a <code>pep</code> section to the configuration (<code>python3 scripts/configure_iya_sts.py --pep</code> sets one up) and build with the <code>local</code> (or <code>pep</code>) feature; see <code>docs/remote-pep.md</code>.</p>",
            escape(v["why"].as_str().unwrap_or(""))
        ));
    }
    let text = |x: &Value| match x {
        Value::String(s) if s.is_empty() => "—".to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "yes".into() } else { "no".into() },
        Value::Null => "—".into(),
        other => other.to_string(),
    };
    let dur = |x: &Value, ago: bool| human(x.as_u64().map(Duration::from_millis), ago);
    let micros = |x: &Value| x.as_u64().map(|m| if m >= 1000 { format!("{:.1} ms", m as f64 / 1000.0) } else { format!("{m} µs") }).unwrap_or_else(|| "—".into());
    let (p, d, c) = (&v["policy"], &v["decisions"], &v["controlPlane"]);
    let local = v["mode"] == "local";
    let mut decisions = vec![
        ("Decisions".to_string(), text(&d["total"])),
        ("Allowed".into(), text(&d["allowed"])),
        ("Denied".into(), text(&d["denied"])),
        ("Unavailable (no decision; refused)".into(), text(&d["unavailable"])),
        ("Stopped by an obligation".into(), text(&d["undischargeable"])),
        ("Mean time per decision".into(), micros(&d["meanMicros"])),
        ("Slowest decision".into(), micros(&d["maxMicros"])),
    ];
    if !local {
        decisions.push(("Permit cache".into(), format!("{} held, {} answered from it", text(&d["permitCacheEntries"]), text(&d["permitCacheHits"]))));
    }
    let mut policy = vec![
        ("Policies held".to_string(), if local { text(&p["count"]) } else { "— (central mode: iya-sts decides)".into() }),
        ("Last policy update".into(), dur(&p["sinceUpdateMs"], true)),
        ("Last pull (changed or not)".into(), dur(&p["sinceLastPullMs"], true)),
        ("Next scheduled pull".into(), dur(&p["untilNextPullMs"], false)),
        ("Pulls".into(), format!("{} ({} brought changes, {} failed)", text(&p["pulls"]), text(&p["pullsChanged"]), text(&p["pullFailures"]))),
        ("Policy-change events".into(), format!("{} acted on, {} for another PEP; last {}", text(&p["eventsReceived"]), text(&p["eventsIgnored"]), dur(&p["sinceLastEventMs"], true))),
        ("Catalogue claims sent".into(), text(&p["catalogueSubjectClaims"])),
    ];
    if local {
        policy.push(("Policy set version".into(), text(&p["syncToken"])));
    }
    policy.push(("Catalogue version".into(), text(&p["catalogueToken"])));
    let the_pep = vec![
        ("Name".to_string(), text(&v["name"])),
        ("Mode".into(), text(&v["mode"])),
        ("Application".into(), text(&v["application"])),
        ("iya-sts".into(), text(&v["pdpUrl"])),
        ("Registered".into(), text(&v["registered"])),
        ("Running".into(), format!("{} (up {})", text(&v["running"]), dur(&c["uptimeMs"], false).trim_start_matches("in "))),
        ("Policy-change events on the stream".into(), text(&v["eventStream"])),
        ("Protocol version".into(), text(&v["protocolVersion"])),
        ("Key thumbprint".into(), text(&v["keyThumbprint"])),
    ];
    let control = vec![
        ("Heartbeats".to_string(), format!("{} ({} failed)", text(&c["heartbeats"]), text(&c["heartbeatFailures"]))),
        ("Last heartbeat".into(), dur(&c["sinceLastHeartbeatMs"], true)),
        ("Next heartbeat".into(), dur(&c["untilNextHeartbeatMs"], false)),
        ("Registrations".into(), text(&c["registrations"])),
        ("Decision records".into(), format!("{} queued, {} sent, {} dropped", text(&c["recordsQueued"]), text(&c["recordsShipped"]), text(&c["recordsDropped"]))),
    ];
    let mut out = String::new();
    let problems = v["problems"].as_str().unwrap_or("");
    if !problems.is_empty() {
        out.push_str(&pane("pep-problems", "Problems", "", &format!("<p class=\"problem\">{}</p>", escape(problems))));
    }
    for (title, rows) in [("Decisions", decisions), ("Cached policy", policy), ("The PEP", the_pep), ("Control plane", control)] {
        let id: String = format!("pep-{}", title.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect::<String>());
        out.push_str(&format!("<details class=\"card pane\" id=\"{id}\" open><summary><h2>{}</h2></summary><table class=\"facts\">", escape(title)));
        for (k, val) in rows {
            out.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", escape(&k), escape(&val)));
        }
        out.push_str("</table></details>");
    }
    out.push_str("<details class=\"card pane\" id=\"pep-try\" open><summary><h2>Try it</h2></summary><ul class=\"checks\">\
<li><a href=\"/orders/42\">/orders/42</a> <span class=\"muted\">read an order: permitted when your grant's ID token assertion carried an acr</span></li>\
<li><a href=\"/attribute-protected\">/attribute-protected</a> <span class=\"muted\">permitted when your directory attribute attr1 is abc123, which the PEP asks iya-sts's PIP for</span></li>\
</ul><p><small>Each is decided by this PEP against the demo application's own policy; the counters above move as you try them.</small></p></details>");
    out.push_str("<p><small>Refreshed every 2 seconds. <a href=\"/pep-status\">As JSON</a>.</small></p>");
    out
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// A redirect to a page of this demo after a form.
fn see_other(location: &str) -> Outcome {
    reply(303, vec![("location".into(), location.into()), ("cache-control".into(), "no-store".into())], Vec::new())
}

/// One received Shared Signals event, as the CAEP & RISC events tab draws
/// it and `app.js` receives it from `/api/signals`.
#[derive(Clone)]
struct LiveEvent {
    id: u64,
    event_type: String,
    jti: String,
    /// CAEP, RISC, SSF (the stream's own) or STS (iya-sts's own).
    family: String,
    at: String,
    subject: String,
    members: Value,
    ended: bool,
}

impl LiveEvent {
    fn of(id: u64, event: &SignalEvent) -> Self {
        let mut subject: Vec<String> = event
            .subject
            .iter()
            .map(|(k, v)| format!("{k} {}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
            .collect();
        subject.sort();
        LiveEvent {
            id,
            event_type: event.event_type.clone(),
            jti: event.jti.clone(),
            family: family_of(&event.event_type).to_string(),
            at: utc(event.iat.unwrap_or_else(now_secs)),
            subject: subject.join(", "),
            members: event.payload.clone(),
            ended: event.ended,
        }
    }
}

/// The most events kept; the oldest go first.
const MAX_EVENTS: usize = 200;

/// The family a SET event type belongs to, for its badge.
fn family_of(event_type: &str) -> &'static str {
    if event_type.contains("/caep/") {
        "CAEP"
    } else if event_type.contains("/risc/") {
        "RISC"
    } else if event_type.contains("/ssf/") {
        "SSF"
    } else {
        "STS"
    }
}

/// A UTC timestamp, `YYYY-MM-DD HH:MM:SS UTC`.
fn utc(secs: f64) -> String {
    let t = secs.max(0.0) as i64;
    let (days, rem) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// A JWT's header and claims, decoded but not verified here: an access
/// token is the resource server's to verify. `None` for a token that is not
/// a signed JWT.
fn decode_jwt(token: &str) -> Option<(Value, Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let part = |p: &str| -> Option<Value> {
        let raw = URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok()?;
        serde_json::from_slice(&raw).ok()
    };
    Some((part(parts[0])?, part(parts[1])?))
}

/// A short, non-reversible name for a token: what the page shows instead of
/// the value, which never leaves this process.
fn token_fingerprint(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("sha256 {hex}…")
}

/// The RFC 7638 thumbprint of a public JWK (EC, RSA or OKP), base64url.
fn jwk_thumbprint(jwk: &serde_json::Map<String, Value>) -> String {
    let get = |k: &str| jwk.get(k).and_then(Value::as_str).unwrap_or("");
    let canonical = match get("kty") {
        "EC" => format!("{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}", get("crv"), get("x"), get("y")),
        "RSA" => format!("{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}", get("e"), get("n")),
        "OKP" => format!("{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{}\"}}", get("crv"), get("x")),
        _ => return String::new(),
    };
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// A claim's value as the Session pane shows it: times read as UTC.
fn claim_text(name: &str, value: &Value) -> String {
    match (name, value) {
        ("iat" | "exp" | "nbf" | "auth_time", Value::Number(n)) => n.as_f64().map(|t| format!("{} ({})", utc(t), n)).unwrap_or_default(),
        (_, Value::String(s)) => s.clone(),
        (_, Value::Array(a)) if a.iter().all(|v| v.is_string()) => a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "),
        (_, other) => other.to_string(),
    }
}

fn claims_table(claims: &serde_json::Map<String, Value>) -> String {
    let mut names: Vec<&String> = claims.keys().collect();
    names.sort();
    let rows: String = names.iter().map(|n| format!("<tr><th>{}</th><td>{}</td></tr>", escape(n), escape(&claim_text(n, &claims[*n])))).collect();
    format!("<table class=\"facts\">{rows}</table>")
}

/// Seconds as a person reads them, `ago` when negative.
fn in_words(secs: f64) -> String {
    let s = secs.abs().round() as i64;
    let text = if s >= 3600 { format!("{}h {}m", s / 3600, s % 3600 / 60) } else if s >= 60 { format!("{}m {}s", s / 60, s % 60) } else { format!("{s}s") };
    if secs < 0.0 { format!("{text} ago") } else { text }
}

/// A collapsible pane, open, with a stable id.
fn pane(id: &str, title: &str, aside: &str, body: &str) -> String {
    let aside = if aside.is_empty() { String::new() } else { format!(" <span class=\"aside\">{}</span>", escape(aside)) };
    format!("<details class=\"card pane\" id=\"{id}\" open><summary><h2>{}</h2>{aside}</summary>{body}</details>", escape(title))
}

/// One credential on the Tokens pane: its fingerprint and, for a JWT, its
/// decoded header and claims. Never its value.
fn token_block(title: &str, token: &str, note: &str) -> String {
    if token.is_empty() {
        return format!("<h3>{}</h3><p><small>None was issued.</small></p>", escape(title));
    }
    let note = if note.is_empty() { String::new() } else { format!(" · {}", escape(note)) };
    let head = format!("<h3>{}</h3><p><small>{}{note}</small></p>", escape(title), escape(&token_fingerprint(token)));
    match decode_jwt(token) {
        Some((header, claims)) => format!(
            "{head}<p><small>JWT header</small></p><pre class=\"output\">{}</pre><p><small>JWT claims</small></p><pre class=\"output\">{}</pre>",
            escape(&serde_json::to_string_pretty(&header).unwrap_or_default()),
            escape(&serde_json::to_string_pretty(&claims).unwrap_or_default())
        ),
        None if token.split('.').count() == 5 => format!("{head}<p><small>An encrypted JWT (JWE): only its recipient can read it.</small></p>"),
        None => format!("{head}<p><small>Opaque to this client: only iya-sts can read it.</small></p>"),
    }
}

/// The Session tab: what protects the sign-in, who signed in, the grant's
/// token cache and its credentials. GNAP has no ID token of its own and no
/// refresh token: the grant carries an access token (bound to this client's
/// key unless it is a bearer token), a token management URI with its own
/// access token (to rotate it), a continuation URI with its own (to revoke
/// the grant), and the subject (identifiers, and an ID token assertion when
/// one was asked for). Their values stay in this process; the page shows
/// what is in them and a fingerprint, never a value.
fn session_panes(client: &Client, session: &SessionRecord, problem: Option<String>, rotations: &Rotations, stream: &str, notice: &str) -> String {
    let config = &client.config;
    let grant = &session.grant;
    let key = &config.key;
    let thumb = jwk_thumbprint(&key.jwk);
    let short = thumb.chars().take(12).collect::<String>();
    let proof = match key.proof.as_str() {
        "httpsig" => format!("HTTP Message Signatures (RFC 9421), {}, on every request to iya-sts", key.alg),
        "jwsd" => format!("a detached JWS (RFC 9635 section 7.3.3), {}, on every request to iya-sts", key.alg),
        "mtls" => "mutual TLS: this client's certificate on every connection to iya-sts".to_string(),
        other => other.to_string(),
    };
    let instance = match grant.instance_id.as_deref().filter(|_| config.use_instance_id) {
        Some(id) => format!("instance id {id}: the key is sent once, then named"),
        None => "the key is sent with every grant request".to_string(),
    };
    let interaction = format!(
        "finish by {}; the {} interaction hash over both nonces checked on return; the pending grant in a sealed cookie for /callback only, 10 minutes",
        config.finish_method, config.hash_method
    );
    let bound = if grant.bearer { "a bearer token" } else { "bound to this client's key: each use is signed" };
    let binding = if config.require_bound_tokens { format!("{bound}; a bearer token is refused") } else { format!("{bound}; bearer tokens are accepted") };
    let subject = if session.person.as_ref().is_some_and(|p| p.assertion_verified) {
        format!("the ID token assertion verified against {}'s keys, its subject matched to the identifier", config.id_token_issuer)
    } else {
        "subject identifiers only: no ID token assertion was asked for or returned".to_string()
    };
    let protections = [
        ("Key proof", proof),
        ("Client key", format!("{} {}, thumbprint {short}…", key.jwk.get("kty").and_then(Value::as_str).unwrap_or("?"), key.alg)),
        ("Client instance", instance),
        ("Interaction", interaction),
        ("Access token", binding),
        ("Subject", subject),
        ("TLS", if config.tls_ca.is_empty() { "iya-sts is verified against the system's roots".to_string() } else { "iya-sts is verified against tlsCa's trust chain".to_string() }),
        ("Token cache", "server-side, in this process; never sent to the browser".to_string()),
        ("Shared Signals", if stream.is_empty() { "not running".to_string() } else { stream.to_string() }),
    ];
    let list: String = protections.iter().map(|(k, v)| format!("<li><strong>{}</strong> <span class=\"muted\">{}</span></li>", escape(k), escape(v))).collect();
    let mut out = String::new();
    if !notice.is_empty() {
        out.push_str(&format!("<p class=\"notice\">{}</p>", escape(notice)));
    }
    out.push_str(&pane("security-card", "Protections in effect", "", &format!("<ul class=\"checks\">{list}</ul>")));

    let who = match &session.person {
        Some(person) => {
            let mut ids = vec![("Subject (sub)".to_string(), person.sub.clone())];
            if let Some(iss) = &person.iss {
                ids.push(("Issuer".into(), iss.clone()));
            }
            if let Some(uid) = &person.uid {
                ids.push(("Account username".into(), uid.clone()));
            }
            if let Some(sid) = &person.sid {
                ids.push(("iya-sts session".into(), sid.clone()));
            }
            let rows: String = ids.iter().map(|(k, v)| format!("<tr><th>{}</th><td>{}</td></tr>", escape(k), escape(v))).collect();
            let claims = if person.claims.is_empty() {
                "<p><small>No ID token assertion: the grant returned subject identifiers only.</small></p>".to_string()
            } else {
                format!("<p><small>Every claim of the ID token assertion the grant returned, as the library verified it.</small></p>{}", claims_table(&person.claims))
            };
            format!("<p><small>The subject the grant names.</small></p><table class=\"facts\">{rows}</table>{claims}")
        }
        None => "<p><small>The grant names no subject.</small></p>".to_string(),
    };
    let issued = session
        .person
        .as_ref()
        .and_then(|p| p.claims.get("auth_time"))
        .and_then(Value::as_f64)
        .map(|t| format!("signed in {}", in_words(t - now_secs())))
        .unwrap_or_default();
    out.push_str(&pane("session-card", "Session", &issued, &who));

    let at = now_secs();
    let expires = grant.expires_at.map(|ms| ms / 1000.0);
    let expiry = expires.map(|e| format!("{} ({})", in_words(e - at), utc(e))).unwrap_or_else(|| "not stated".into());
    let auto = match (expires, &grant.manage) {
        (Some(e), Some(_)) => format!("{} (when 60 s or less are left and the page asks for it)", in_words((e - 60.0 - at).max(0.0))),
        (_, None) => "— (the grant has no token management URI)".into(),
        (None, Some(_)) => "— (the token states no expiry)".into(),
    };
    let last = rotations.last.map(|t| in_words(t - at)).unwrap_or_else(|| "none yet".into());
    let status = match &problem {
        None if expires.is_some_and(|e| e <= at) => "expired".to_string(),
        None => format!("{}, valid", if grant.bearer { "bearer access token" } else { "key-bound access token" }),
        Some(why) => format!("no valid access token ({why})"),
    };
    let rights = serde_json::to_string_pretty(&grant.access).unwrap_or_default();
    let cache = format!(
        "<table class=\"facts\"><tr><th>Access token</th><td>{}</td></tr><tr><th>Expires in</th><td>{}</td></tr><tr><th>Auto-rotation in</th><td>{}</td></tr><tr><th>Last rotation</th><td>{}</td></tr><tr><th>Rotations</th><td>{}</td></tr><tr><th>Token management</th><td>{}</td></tr><tr><th>Grant continuation</th><td>{}</td></tr><tr><th>Grant</th><td>{}</td></tr></table>\
<p><small>Access rights granted</small></p><pre class=\"output\">{}</pre>\
<form class=\"inline\" method=\"post\" action=\"/session/rotate\"><button type=\"submit\" class=\"secondary\"{}>Rotate now</button></form>",
        escape(&status),
        escape(&expiry),
        escape(&auto),
        escape(&last),
        rotations.count,
        if grant.manage.is_some() { "held: the access token can be rotated" } else { "none" },
        if grant.continuation.is_some() { "held: Sign out revokes the grant" } else { "none" },
        escape(grant.grant_id.as_deref().unwrap_or("—")),
        escape(&rights),
        if grant.manage.is_none() { " disabled" } else { "" }
    );
    out.push_str(&pane("token-card", "Token cache", &format!("{} rotation(s)", rotations.count), &cache));
    let tokens = format!(
        "<p><small>As currently cached{}. The values stay in this process: each is shown by a fingerprint, and a JWT by its decoded header and claims.</small></p>{}{}{}<h3>ID token assertion</h3><p><small>{}</small></p>",
        if rotations.count > 0 { format!(" (after {} rotation(s))", rotations.count) } else { String::new() },
        token_block("GNAP access token", &grant.access_token, if grant.bearer { "bearer" } else { "key-bound" }),
        token_block("Token management access token", grant.manage.as_ref().map(|m| m.access_token.as_str()).unwrap_or(""), "rotates the access token"),
        token_block("Grant continuation access token", grant.continuation.as_ref().map(|c| c.access_token.as_str()).unwrap_or(""), "continues or revokes the grant"),
        if session.person.as_ref().is_some_and(|p| p.assertion_verified) {
            "Its verified claims are on the Session pane. The assertion itself is not kept once it is verified."
        } else {
            "None was returned."
        }
    );
    out.push_str(&pane("tokens-card", "Tokens", "", &tokens));
    out
}

fn event_json(event: &LiveEvent) -> Value {
    serde_json::json!({
        "id": event.id, "type": event.event_type, "jti": event.jti, "family": event.family,
        "at": event.at, "subject": event.subject, "members": event.members, "ended": event.ended,
        "about": if event.family == "SSF" { "stream" } else { "subject" },
    })
}

/// One log entry: the same markup `app.js`'s `entryNode()` draws.
fn event_item(event: &LiveEvent) -> String {
    let short = event.event_type.rsplit("/event-type/").next().unwrap_or(&event.event_type);
    let outcome = if event.family == "SSF" {
        "about the stream: the verification this session asked for"
    } else if event.ended {
        "ended this session"
    } else {
        "recorded; this session continues"
    };
    let mut out = format!(
        "<li class=\"log-item\" data-id=\"{}\"><div class=\"log-top\"><span class=\"badge {}\">{}</span> <strong>{}</strong> <time>{}</time></div><p class=\"log-outcome{}\">{}</p>",
        event.id,
        escape(&event.family.to_lowercase()),
        escape(&event.family),
        escape(short),
        escape(&event.at),
        if event.ended { " ended" } else { "" },
        outcome
    );
    if !event.subject.is_empty() {
        out.push_str(&format!("<p><small>Subject: {}</small></p>", escape(&event.subject)));
    }
    if let Some(members) = event.members.as_object().filter(|m| !m.is_empty()) {
        out.push_str("<table class=\"facts members\">");
        for (name, value) in members {
            if name == "subject" {
                continue;
            }
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Object(o) if !o.is_empty() && o.values().all(|v| v.is_string()) => o.values().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" / "),
                other => other.to_string(),
            };
            out.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", escape(name), escape(&text)));
        }
        out.push_str("</table>");
    }
    out.push_str(&format!("<p><small>jti {}</small></p></li>", escape(&event.jti)));
    out
}

/// The CAEP & RISC events tab: whose events these are, the stream with the
/// verification request, and the log, newest first. `app.js` adds what
/// arrives without reloading.
fn events_panel(events: &[LiveEvent], stream: &str, notice: &str) -> String {
    let items: String = events.iter().rev().map(event_item).collect();
    let notice = if notice.is_empty() { String::new() } else { format!("<p class=\"notice\">{}</p>", escape(notice)) };
    // The one stream is the application's, so the log is too: a real
    // application shows a person only events about their own session or
    // account, and keeps the rest from them.
    let scope = pane("events-scope", "Whose events these are", "", "<p class=\"warning\"><strong>Every event this application received, for every user.</strong> This tab lists all the CAEP and RISC events the application's Shared Signals stream delivered: events about other people's sessions and accounts as well as yours. That is for this demonstration only. A real application must take additional safeguards: show a person only the events about their own session or account, and keep the others to the people whose job is to see them.</p>");
    let stream_pane = pane("events-stream", "Shared Signals stream", "", &format!(
        "<table class=\"facts\"><tr><th>Stream status</th><td id=\"stream-status\">{}</td></tr><tr><th>Live</th><td id=\"live-state\">connecting…</td></tr></table>\
<form id=\"verify-form\" method=\"post\" action=\"/signals/verify\"><button type=\"submit\">Ask for a verification event</button></form>",
        escape(stream)
    ));
    let count = if events.is_empty() { String::new() } else { format!("{} event(s)", events.len()) };
    let log_pane = pane("events-log", "Event log", &count, &format!(
        "<p><small>The CAEP and RISC events this application's receiver has accepted, about anybody, newest first, and the verification events it asked for. Each appears here within moments of the receiver getting it.</small></p>\
<ul class=\"log\" id=\"log\">{items}</ul>\
<p class=\"empty\" id=\"log-empty\"{}>No CAEP or RISC event yet. At iya-sts, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>",
        if events.is_empty() { "" } else { " hidden" }
    ));
    format!("{notice}{scope}{stream_pane}{log_pane}")
}

/// A page, with the top bar's links and user menu when someone is signed in.
fn page_for(title: &str, body: &str, who: Option<&SessionRecord>) -> String {
    let menu = who.map(user_menu).unwrap_or_default();
    let nav = if who.is_some() { site_nav() } else { String::new() };
    let script = if who.is_some() { "<script src=\"/menu.js\" defer></script>" } else { "" };
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{}</title>\n<link rel=\"stylesheet\" href=\"/styles.css\">\n</head>\n<body>\n<header class=\"topbar\"><a href=\"/\">gnap-caep-risc demo</a>{nav}{menu}</header>\n<main>\n{body}\n</main>\n<footer>A server-side application signing in with GNAP through gnap-caep-risc.</footer>{script}\n</body>\n</html>\n",
        escape(title)
    )
}

/// The top bar's links between the demo's pages, for a signed-in person:
/// the demo itself, and (with the embedded PEP) the two pages the PEP
/// decides, so each is one click from the others.
fn site_nav() -> String {
    #[allow(unused_mut)]
    let mut links = vec![("/", "Demo home")];
    #[cfg(feature = "pep")]
    links.extend([("/attribute-protected", "Attribute-protected"), ("/orders/42", "Order 42")]);
    let items: Vec<String> = links.iter().map(|(href, label)| format!("<a href=\"{href}\">{label}</a>")).collect();
    format!("<nav class=\"site-nav\" aria-label=\"Demo pages\">{}</nav>", items.join(""))
}

/// The person's username, from what the grant returned about them: the
/// user part of the `account` subject identifier (iya-sts builds it from the
/// directory username), else the ID token assertion's `username` claim
/// (iya-sts's own), else its `preferred_username`. Empty when none is there.
fn username_of(person: &Person) -> String {
    let claim = person.claims.get("username").and_then(Value::as_str).map(str::to_string);
    [person.uid.clone(), claim, person.preferred_username.clone()].into_iter().flatten().find(|v| !v.is_empty()).unwrap_or_default()
}

/// Who a person is, as the heading, the menu and /live-status name them:
/// the username, else the email, and the subject identifier only when
/// nothing else names them.
fn display_name(person: &Person) -> String {
    [username_of(person), person.email.clone().unwrap_or_default(), person.sub.clone()].into_iter().find(|v| !v.is_empty()).unwrap_or_default()
}

/// A session's name: its person's, or the grant's when it names nobody.
fn record_name(session: &SessionRecord) -> String {
    match &session.person {
        Some(person) => display_name(person),
        None => format!("grant {}", session.grant.grant_id.as_deref().unwrap_or("without a subject")),
    }
}

/// The top bar's user menu: the signed-in account, signing in with another
/// account, and signing out. This demo keeps one sign-in per browser.
fn user_menu(session: &SessionRecord) -> String {
    let name = record_name(session);
    let initial = name.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or_else(|| "?".into());
    let detail = session
        .person
        .as_ref()
        .and_then(|p| [p.name.clone(), p.email.clone()].into_iter().flatten().find(|v| !v.is_empty() && *v != name))
        .unwrap_or_default();
    let detail = if detail.is_empty() { String::new() } else { format!("<span class=\"muted small\">{}</span>", escape(&detail)) };
    format!(
        "<details class=\"acct-menu\"><summary aria-label=\"Account menu\"><span class=\"avatar\" aria-hidden=\"true\">{i}</span><span class=\"menu-name\" title=\"{n}\">{n}</span><span class=\"caret\" aria-hidden=\"true\">▾</span></summary>\
<div class=\"menu\" role=\"menu\"><p class=\"menu-head\">Signed in</p>\
<div class=\"menu-row static\"><span class=\"avatar\" aria-hidden=\"true\">{i}</span><span class=\"menu-who\"><span>{n}</span>{detail}</span></div>\
<div class=\"menu-sep\"></div>\
<form method=\"post\" action=\"/login/another\"><button class=\"menu-row\" type=\"submit\" role=\"menuitem\"><span class=\"avatar plus\" aria-hidden=\"true\">+</span>Sign in with another account</button></form>\
<p class=\"muted small menu-note\">GNAP has no way to make iya-sts ask again: this signs you out here (the grant is revoked) and back to the sign-in page. iya-sts asks who you are unless it still holds a sign-on session for you.</p>\
<div class=\"menu-sep\"></div>\
<form method=\"post\" action=\"/logout\"><button class=\"menu-row\" type=\"submit\" role=\"menuitem\">Sign out {n}</button></form></div></details>",
        i = escape(&initial),
        n = escape(&name)
    )
}

fn plain(status: u16, body: &str) -> Outcome {
    reply(status, vec![("content-type".into(), "text/plain".into())], body.as_bytes().to_vec())
}

fn reply(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Outcome {
    Outcome { outgoing: Outgoing { status, headers, body }, watch: None }
}

fn reply_only(outgoing: Outgoing) -> Outcome {
    Outcome { outgoing, watch: None }
}

fn json_err(err: &str) -> Outcome {
    let body = serde_json::to_vec(&serde_json::json!({"error": err})).unwrap_or_else(|_| b"{\"error\":\"sign-in failed\"}".to_vec());
    reply(400, vec![("content-type".into(), "application/json".into())], body)
}

fn cookie_value<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    let prefix = format!("{name}=");
    for (key, value) in headers {
        if key == "cookie" {
            for part in value.split(';') {
                let item = part.trim();
                if let Some(rest) = item.strip_prefix(&prefix) {
                    return rest;
                }
            }
        }
    }
    ""
}

fn ids_of(value: &Value) -> Vec<String> {
    value.get("ids").and_then(|item| item.as_array()).map(|list| list.iter().filter_map(|item| item.as_str().map(|text| text.to_string())).collect()).unwrap_or_default()
}

fn escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn random_token() -> String {
    let mut buf = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = if key.len() > 64 { Sha256::digest(key).to_vec() } else { key.to_vec() };
    key_block.resize(64, 0);
    let mut inner_key = [0u8; 64];
    let mut outer_key = [0u8; 64];
    for index in 0..64 {
        inner_key[index] = key_block[index] ^ 0x36;
        outer_key[index] = key_block[index] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn constant_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for index in 0..left.len() {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

struct Moved {
    finish: String,
    display: String,
}

fn redirects_for(finish: &str, display: &str, public: &str, given: bool, port: &str) -> Moved {
    if given && !public.is_empty() {
        return Moved {
            finish: replace_origin(finish, public),
            display: if display.is_empty() { String::new() } else { replace_origin(display, public) },
        };
    }
    if !port.is_empty() {
        return Moved {
            finish: if finish.is_empty() { String::new() } else { on_port(finish, port) },
            display: if display.is_empty() { String::new() } else { on_port(display, port) },
        };
    }
    Moved { finish: finish.to_string(), display: display.to_string() }
}

fn on_port(raw: &str, port: &str) -> String {
    let Ok(port_n) = port.parse::<u16>() else { return raw.to_string() };
    if port_n == 0 {
        return raw.to_string();
    }
    let Ok(mut parsed) = url::Url::parse(raw) else { return raw.to_string() };
    let Some(host) = parsed.host_str() else { return raw.to_string() };
    let lower = host.to_ascii_lowercase();
    if lower != "localhost" && lower != "127.0.0.1" && lower != "::1" {
        return raw.to_string();
    }
    if parsed.set_port(Some(port_n)).is_err() {
        return raw.to_string();
    }
    parsed.to_string()
}

fn replace_origin(value: &str, public: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let Ok(base) = url::Url::parse(&format!("{}/", public.trim_end_matches('/'))) else { return value.to_string() };
    let Ok(mut next) = url::Url::parse(value) else { return value.to_string() };
    if next.set_scheme(base.scheme()).is_err() {
        return value.to_string();
    }
    if let Some(host) = base.host_str() {
        if next.set_host(Some(host)).is_err() {
            return value.to_string();
        }
    }
    if next.set_port(base.port()).is_err() {
        return value.to_string();
    }
    if next.path().is_empty() {
        next.set_path("/");
    }
    next.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_a_person_reads_them() {
        assert_eq!(human(None, true), "—");
        assert_eq!(human(Some(Duration::from_millis(400)), true), "just now");
        assert_eq!(human(Some(Duration::from_millis(400)), false), "now");
        assert_eq!(human(Some(Duration::from_secs(42)), true), "42 s ago");
        assert_eq!(human(Some(Duration::from_secs(300)), false), "in 5 min 0 s");
        assert_eq!(human(Some(Duration::from_secs(7300)), true), "2 h 1 min ago");
    }

    #[test]
    fn no_client_or_no_pep_says_so() {
        assert!(pep_fragment(None).contains("No embedded PEP"));
        assert_eq!(pep_json(None)["enabled"], false);
    }

    fn request(path: &str, query: &[(&str, &str)]) -> Request {
        Request {
            method: "GET".into(),
            path: path.into(),
            query: query.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn the_status_routes_need_a_session_and_pages_carry_the_csp() {
        let demo = Arc::new(Demo::new("http://127.0.0.1:1".into(), true, "1".into()));
        for path in ["/pep-status", "/pep-status.html"] {
            assert_eq!(demo.dispatch(&request(path, &[])).outgoing.status, 401, "{path} without a session");
        }
        let page = demo.dispatch(&request("/", &[("tab", "pep")])).outgoing;
        let csp = page.headers.iter().find(|(k, _)| k == "content-security-policy").map(|(_, v)| v.clone()).unwrap_or_default();
        assert!(csp.contains("connect-src 'self'"), "pep.js may fetch its fragment: {csp}");
        assert!(csp.contains("script-src 'self'"));
    }

    fn key_pem(seed: u8) -> String {
        use p256::pkcs8::EncodePrivateKey;
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().to_pkcs8_pem(Default::default()).unwrap().to_string()
    }

    /// A client nothing answers for (no network is used to build it).
    fn offline_client(tag: &str) -> Client {
        let dir = std::env::temp_dir().join(format!("gnap-demo-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = serde_json::json!({
            "grantEndpoint": "http://127.0.0.1:9/gnap", "application": "demo", "privateKey": key_pem(6),
            "keyProof": "httpsig", "allowInsecure": true, "signals": false, "access": ["orders.read"],
        });
        let client = Client::create(Client::resolve(&doc, &dir).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        client
    }

    fn person_named(uid: Option<&str>, claims: Value) -> Person {
        let claims = claims.as_object().cloned().unwrap_or_default();
        Person {
            sub: "urn:uuid:3e0f".into(),
            preferred_username: claims.get("preferred_username").and_then(Value::as_str).map(str::to_string),
            email: claims.get("email").and_then(Value::as_str).map(str::to_string),
            name: claims.get("name").and_then(Value::as_str).map(str::to_string),
            assertion_verified: !claims.is_empty(),
            claims,
            iss: Some("https://sts.example".into()),
            uid: uid.map(str::to_string),
            sid: None,
            acr: None,
            amr: Vec::new(),
        }
    }

    fn record(person: Option<Person>, access_token: &str) -> SessionRecord {
        let cont = |token: &str| gnap_caep_risc::Continuation { uri: "https://sts.example/gnap/continue/g1".into(), access_token: token.into(), wait: None };
        SessionRecord {
            person,
            grant: Grant {
                access_token: access_token.into(),
                bearer: false,
                access: serde_json::json!(["ssf.read", "ssf.manage"]),
                expires_in: Some(600.0),
                expires_at: Some(now_secs() * 1000.0 + 600_000.0),
                manage: Some(cont("manage-secret-value")),
                continuation: Some(cont("continue-secret-value")),
                instance_id: None,
                subject: None,
                grant_id: Some("g1".into()),
            },
        }
    }

    fn live(id: u64, event_type: &str, ended: bool) -> LiveEvent {
        LiveEvent {
            id,
            event_type: event_type.into(),
            jti: format!("j<{id}>"),
            family: family_of(event_type).into(),
            at: utc(1_795_000_000.0),
            subject: "format email, email <a@x>".into(),
            members: serde_json::json!({"reason_admin": {"en": "<b>gone</b>"}, "subject": {"x": 1}}),
            ended,
        }
    }

    #[test]
    fn the_events_tab_draws_each_event_newest_first_and_escapes() {
        let caep = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
        let risc = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
        let html = events_panel(&[live(1, caep, true), live(2, risc, false)], "polling <s>", "");
        assert!(html.find("data-id=\"2\"").unwrap() < html.find("data-id=\"1\"").unwrap(), "newest first");
        assert!(html.contains("<span class=\"badge caep\">CAEP</span> <strong>session-revoked</strong>"));
        assert!(html.contains("<span class=\"badge risc\">RISC</span>"));
        assert!(html.contains("ended this session") && html.contains("recorded; this session continues"));
        assert!(html.contains("&lt;b&gt;gone&lt;/b&gt;") && !html.contains("<b>gone"), "members escaped");
        assert!(html.contains("polling &lt;s&gt;") && html.contains("jti j&lt;1&gt;"));
        assert!(!html.contains(">subject<"), "the subject member is the Subject line, not a row");
        assert!(html.contains("id=\"log-empty\" hidden"), "the empty note is hidden once there are events");
        assert!(events_panel(&[], "", "").contains("id=\"log-empty\">"), "and shown when there are none");
        assert!(html.contains("<strong>Every event this application received, for every user.</strong>"), "the tab says whose events they are");
        assert!(html.contains("additional safeguards") && events_panel(&[], "", "").contains("for every user"), "with or without events");
        for id in ["events-scope", "events-stream", "events-log"] {
            assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open>")), "{id} is a collapsible pane");
        }
        assert!(html.contains("id=\"live-state\"") && html.contains("id=\"stream-status\"") && html.contains("id=\"verify-form\""), "app.js finds what it updates");
    }

    #[test]
    fn a_received_event_becomes_what_app_js_reads() {
        let mut subject = serde_json::Map::new();
        subject.insert("format".into(), Value::from("email"));
        subject.insert("email".into(), Value::from("a@example.com"));
        let event = SignalEvent {
            event_type: "https://schemas.openid.net/secevent/ssf/event-type/verification".into(),
            payload: serde_json::json!({"state": "demo-1"}),
            subject,
            jti: "j1".into(),
            sessions: Vec::new(),
            ended: false,
            iat: Some(0.0),
            txn: None,
        };
        let e = event_json(&LiveEvent::of(7, &event));
        assert_eq!((e["id"].clone(), e["family"].clone(), e["about"].clone()), (Value::from(7), Value::from("SSF"), Value::from("stream")));
        assert_eq!(e["subject"], "email a@example.com, format email", "sorted, the values as text");
        assert_eq!(e["at"], "1970-01-01 00:00:00 UTC");
        assert_eq!(e["members"]["state"], "demo-1");
        assert_eq!(family_of("urn:iya:sts:secevent:event-type:pep-policies-changed"), "STS");
        assert_eq!(utc(1_795_000_000.0), "2026-11-18 11:06:40 UTC");
    }

    #[test]
    fn a_token_is_shown_by_fingerprint_and_a_jwt_by_its_claims() {
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let jwt = format!("{}.{}.sig", enc(&serde_json::json!({"alg": "ES256", "typ": "at+jwt"})), enc(&serde_json::json!({"sub": "<s>", "uid": "alice"})));
        let (h, c) = decode_jwt(&jwt).expect("a JWT");
        assert_eq!((h["alg"].clone(), c["uid"].clone()), (Value::from("ES256"), Value::from("alice")));
        assert!(decode_jwt("opaque").is_none() && decode_jwt("a.b.c.d.e").is_none());
        let block = token_block("GNAP access token", &jwt, "key-bound");
        assert!(block.contains("&quot;sub&quot;: &quot;&lt;s&gt;&quot;"), "decoded and escaped");
        assert!(!block.contains(&jwt), "the value itself is never on the page");
        assert!(block.contains("sha256 ") && block.contains("key-bound"));
        assert!(token_block("t", "opaque", "").contains("Opaque"));
        assert!(token_block("t", "", "").contains("None was issued"));
        assert!(token_block("t", "a.b.c.d.e", "").contains("JWE"));
        assert_eq!(token_fingerprint("x"), token_fingerprint("x"));
        assert_ne!(token_fingerprint("x"), token_fingerprint("y"));
    }

    #[test]
    fn the_thumbprint_is_rfc_7638s() {
        // RFC 7638 section 3.1's example key.
        let jwk = serde_json::json!({"kty": "RSA", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"});
        assert_eq!(jwk_thumbprint(jwk.as_object().unwrap()), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        assert_eq!(jwk_thumbprint(serde_json::json!({"kty": "oct"}).as_object().unwrap()), "");
    }

    #[test]
    fn claims_read_as_a_person_reads_them() {
        let claims = serde_json::json!({"auth_time": 0, "amr": ["pwd", "hwk"], "name": "<b>"}).as_object().unwrap().clone();
        let table = claims_table(&claims);
        assert!(table.contains("1970-01-01 00:00:00 UTC (0)"));
        assert!(table.contains("pwd, hwk") && table.contains("&lt;b&gt;"));
        assert!(table.find(">amr<").unwrap() < table.find(">auth_time<").unwrap(), "sorted by name");
        assert_eq!(in_words(90.0), "1m 30s");
        assert_eq!(in_words(-3700.0), "1h 1m ago");
    }

    #[test]
    fn the_session_tab_shows_the_grant_and_never_a_credential() {
        let client = offline_client("session");
        let jwt = format!("{}.{}.sig", URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#), URL_SAFE_NO_PAD.encode(r#"{"uid":"alice"}"#));
        let person = person_named(Some("alice"), serde_json::json!({"sub": "urn:uuid:3e0f", "acr": "urn:example:mfa", "auth_time": 1_700_000_000}));
        let session = record(Some(person), &jwt);
        let html = session_panes(&client, &session, None, &Rotations { count: 2, last: Some(now_secs() - 30.0) }, "polling stream s1", "The access token was rotated.");
        for id in ["security-card", "session-card", "token-card", "tokens-card"] {
            assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open>")), "{id} is a collapsible pane");
        }
        assert!(html.contains("HTTP Message Signatures (RFC 9421), ES256"), "the key proof in effect");
        assert!(html.contains("bound to this client&#39;s key") || html.contains("bound to this client's key"), "a key-bound token");
        assert!(html.contains("ID token assertion verified"), "the subject's assertion");
        assert!(html.contains("<th>Account username</th><td>alice</td>") && html.contains("urn:example:mfa"));
        assert!(html.contains("2 rotation(s)") && html.contains("action=\"/session/rotate\""));
        assert!(html.contains("key-bound access token, valid"));
        assert!(html.contains("&quot;ssf.read&quot;"), "the access rights granted");
        assert!(html.contains("The access token was rotated."));
        for secret in [jwt.as_str(), "manage-secret-value", "continue-secret-value"] {
            assert!(!html.contains(secret), "no credential's value is on the page");
        }
        assert!(html.contains(&token_fingerprint("manage-secret-value")) && html.contains(&token_fingerprint("continue-secret-value")));

        let mut bare = record(None, "opaque");
        bare.grant.manage = None;
        bare.grant.bearer = true;
        let html = session_panes(&client, &bare, Some("it expired".into()), &Rotations::default(), "", "");
        assert!(html.contains("The grant names no subject") && html.contains("a bearer token"));
        assert!(html.contains("no valid access token (it expired)") && html.contains(" disabled>Rotate now"), "nothing to rotate with");
        assert!(html.contains("subject identifiers only"));
    }

    #[test]
    fn the_name_shown_is_the_username_never_the_subject_when_there_is_one() {
        assert_eq!(display_name(&person_named(Some("alice"), serde_json::json!({"username": "a-claim", "preferred_username": "p"}))), "alice", "the account identifier's user part first");
        assert_eq!(display_name(&person_named(None, serde_json::json!({"username": "a-claim", "preferred_username": "p"}))), "a-claim", "then iya-sts's username claim");
        assert_eq!(display_name(&person_named(None, serde_json::json!({"preferred_username": "p", "email": "e@x"}))), "p");
        assert_eq!(display_name(&person_named(None, serde_json::json!({"email": "e@x"}))), "e@x");
        assert_eq!(display_name(&person_named(None, serde_json::json!({}))), "urn:uuid:3e0f", "the subject only when nothing else names them");
        assert_eq!(record_name(&record(None, "t")), "grant g1");
    }

    #[test]
    fn the_user_menu_names_the_account_and_holds_sign_out() {
        let person = person_named(Some("alice"), serde_json::json!({"name": "<Alice> Admin", "email": "alice@example.com"}));
        let menu = user_menu(&record(Some(person), "t"));
        assert!(menu.contains("<span class=\"avatar\" aria-hidden=\"true\">A</span>"), "{menu}");
        assert!(menu.contains("title=\"alice\">alice</span>") && menu.contains("Sign out alice"));
        assert!(menu.contains("&lt;Alice&gt; Admin") && !menu.contains("<Alice>"), "the name is the detail line, escaped");
        assert!(menu.contains("<form method=\"post\" action=\"/login/another\">"), "another account is a POST: it ends this sign-in");
        assert!(menu.contains("<form method=\"post\" action=\"/logout\"><button class=\"menu-row\""), "sign out is a POST, in the menu");
        let page = page_for("x", "<p>body</p>", Some(&record(None, "t")));
        assert!(page.contains("acct-menu") && page.contains("/menu.js") && page.contains("class=\"site-nav\""));
        assert!(page.contains("href=\"/\">Demo home</a>"));
        #[cfg(feature = "pep")]
        assert!(page.contains("href=\"/attribute-protected\"") && page.contains("href=\"/orders/42\""), "{page}");
        let anonymous = page_for("x", "", None);
        assert!(!anonymous.contains("acct-menu") && !anonymous.contains("site-nav"), "no menu and no links before a sign-in");
    }

    #[test]
    fn every_page_script_keeps_its_names_to_itself_and_the_toggle_ships_hidden() {
        for (name, src) in [
            ("app.js", include_str!("../../demo/public/app.js")),
            ("pep.js", include_str!("../../demo/public/pep.js")),
            ("panes.js", include_str!("../../demo/public/panes.js")),
            ("menu.js", include_str!("../../demo/public/menu.js")),
        ] {
            let code: Vec<&str> = src.lines().filter(|l| !l.trim_start().starts_with("//") && !l.trim().is_empty()).collect();
            assert_eq!(code.first().copied(), Some("(() => {"), "{name} opens its own scope");
            assert_eq!(code.last().copied(), Some("})();"), "{name} closes it");
        }
        assert!(include_str!("../../demo/public/styles.css").contains("[hidden] { display: none !important; }"), "hidden hides a button too");
        let panes = include_str!("../../demo/public/panes.js");
        assert!(panes.contains("panes-toggle") && panes.contains("Expand all") && panes.contains("panes-redrawn"));
        assert!(include_str!("../../demo/public/pep.js").contains("panes-redrawn"), "pep.js tells the toggle when it redrew");
        assert!(include_str!("demo.rs").contains("id=\\\"panes-toggle\\\" hidden>Collapse all"), "hidden until the script shows it");
    }

    /// A demo with no configuration to read, and one signed-in browser.
    fn signed_in_demo(tag: &str) -> (Arc<Demo>, Vec<(String, String)>) {
        let mut demo = Demo::new("http://127.0.0.1:1".into(), true, "1".into());
        demo.config_path = std::env::temp_dir().join(format!("gnap-demo-none-{tag}-{}", std::process::id())).join("gnap.json");
        demo.public_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("demo/public");
        let person = person_named(Some("alice"), serde_json::json!({}));
        demo.state.lock().unwrap().sessions.insert("s1".into(), record(Some(person), "t"));
        let cookie = format!("gsid={}", demo.seal(&serde_json::json!({"id": "s1"})));
        (Arc::new(demo), vec![("cookie".into(), cookie)])
    }

    fn with(method: &str, path: &str, query: &[(&str, &str)], headers: &[(String, String)]) -> Request {
        let mut req = request(path, query);
        req.method = method.into();
        req.headers = headers.to_vec();
        req
    }

    #[test]
    fn the_signed_in_routes_need_a_session() {
        let (demo, cookie) = signed_in_demo("routes");
        assert_eq!(demo.dispatch(&with("GET", "/api/signals", &[], &[])).outgoing.status, 401);
        let api = demo.dispatch(&with("GET", "/api/signals", &[("after", "0")], &cookie)).outgoing;
        assert_eq!(api.status, 200);
        let body: Value = serde_json::from_slice(&api.body).unwrap();
        assert_eq!(body["events"], serde_json::json!([]));
        assert!(body["streamStatus"]["status"].as_str().unwrap().contains("not started"));
        assert_eq!(demo.dispatch(&with("GET", "/events", &[], &cookie)).outgoing.status, 204, "app.js falls back to polling");
        for path in ["/signals/verify", "/session/rotate"] {
            let out = demo.dispatch(&with("POST", path, &[], &[])).outgoing;
            assert_eq!(out.status, 303, "{path} without a session goes home");
        }
        let verify = demo.dispatch(&with("POST", "/signals/verify", &[], &cookie)).outgoing;
        assert!(verify.headers.iter().any(|(k, v)| k == "location" && v == "/?tab=events&verify=refused"), "no receiver is running");
        for path in ["/panes.js", "/menu.js", "/app.js", "/pep.js"] {
            assert_eq!(demo.dispatch(&with("GET", path, &[], &[])).outgoing.status, 200, "{path} is served");
        }
    }

    #[test]
    fn the_signed_in_page_has_three_tabs_and_sign_out_only_in_the_menu() {
        let (demo, cookie) = signed_in_demo("home");
        let page = demo.dispatch(&with("GET", "/", &[("tab", "events")], &cookie)).outgoing;
        let html = String::from_utf8(page.body).unwrap();
        assert!(html.contains("<h1>Signed in as alice</h1>"));
        assert!(html.contains("href=\"/\"") && html.contains("href=\"/?tab=events\" aria-selected=\"true\"") && html.contains("href=\"/?tab=pep\""));
        assert!(html.contains("id=\"events-log\"") && html.contains("/app.js") && html.contains("/panes.js"));
        assert_eq!(html.matches("action=\"/logout\"").count(), 1, "sign out is in the menu and nowhere else");
        assert!(page.headers.iter().any(|(k, v)| k == "cache-control" && v == "no-store"));
        let another = demo.dispatch(&with("POST", "/login/another", &[], &cookie)).outgoing;
        assert!(another.headers.iter().any(|(k, v)| k == "location" && v == "/?another=1"));
        assert!(another.headers.iter().any(|(k, v)| k == "set-cookie" && v.starts_with("gsid=;")));
        assert!(demo.state.lock().unwrap().sessions.is_empty(), "the sign-in here ended");
        let home = String::from_utf8(demo.dispatch(&with("GET", "/", &[("another", "1")], &cookie)).outgoing.body).unwrap();
        assert!(home.contains("You are signed out of this demo") || home.contains("not configured"), "{home}");
    }

    #[cfg(feature = "pep")]
    #[test]
    fn a_pep_protected_page_is_401_signed_out_and_403_on_any_pep_failure() {
        let (demo, cookie) = signed_in_demo("pep");
        for path in ["/attribute-protected", "/orders/42"] {
            assert_eq!(demo.dispatch(&with("GET", path, &[], &[])).outgoing.status, 401, "{path} without a sign-in");
            let out = demo.dispatch(&with("GET", path, &[], &cookie)).outgoing;
            assert_eq!(out.status, 403, "{path} with no GNAP client to ask: a PEP failure");
            let html = String::from_utf8(out.body).unwrap();
            assert!(html.contains("<title>Forbidden</title>") && html.contains("No decision could be asked for: the GNAP client is not configured"), "{html}");
            assert!(html.contains("acct-menu"), "the menu is on the protected pages too");
        }
    }

    #[cfg(feature = "pep")]
    #[test]
    fn the_tab_draws_every_pane_and_escapes() {
        use p256::pkcs8::EncodePrivateKey;
        let pem = |seed: u8| p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().to_pkcs8_pem(Default::default()).unwrap().to_string();
        let dir = std::env::temp_dir().join(format!("gnap-demo-pep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pep.pem"), pem(4)).unwrap();
        // An application name that must be escaped, and an iya-sts nobody answers on.
        let doc = serde_json::json!({
            "grantEndpoint": "http://127.0.0.1:9/gnap", "application": "<b>app</b>", "privateKey": pem(5),
            "keyProof": "httpsig", "allowInsecure": true,
            "pep": {"name": "pep-demo", "mode": "central", "assertionKey": "pep.pem", "timeoutMs": 300}
        });
        let client = Client::create(Client::resolve(&doc, &dir).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let person = Person { sub: "s".into(), claims: Default::default(), assertion_verified: false, iss: None, uid: Some("alice".into()), email: None, name: None, preferred_username: None, sid: None, acr: None, amr: Vec::new() };
        client.decide(&person, &gnap_caep_risc::pep::Access::new("read", "order", "1"));
        let html = pep_fragment(Some(&client));
        for (title, id) in [("Decisions", "pep-decisions"), ("Cached policy", "pep-cached-policy"), ("The PEP", "pep-the-pep"), ("Control plane", "pep-control-plane")] {
            assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open><summary><h2>{title}</h2></summary>")), "{title}: a collapsible pane, open, with the id pep.js keeps it closed by");
        }
        assert!(html.contains("<th>Decisions</th><td>1</td>"), "the decision was counted");
        assert!(html.contains("<th>Unavailable (no decision; refused)</th><td>1</td>"));
        assert!(html.contains("class=\"problem\""), "iya-sts is unreachable, and the tab says so");
        assert!(html.contains("Permit cache"), "central mode shows the cache");
        assert!(html.contains("&lt;b&gt;app&lt;/b&gt;") && !html.contains("<b>app</b>"), "escaped");
        assert!(!html.contains("<script"), "the fragment carries no script");
        assert!(html.contains("id=\"pep-try\"") && html.contains("href=\"/attribute-protected\"") && html.contains("href=\"/orders/42\""), "the Try it pane links the two protected pages");
        assert!(html.contains("<details class=\"card pane\" id=\"pep-problems\" open>"), "the problem is a pane too");
        let v = pep_json(Some(&client));
        assert_eq!((v["enabled"].clone(), v["mode"].clone(), v["decisions"]["unavailable"].clone()), (Value::Bool(true), Value::from("central"), Value::from(1)));
    }
}
