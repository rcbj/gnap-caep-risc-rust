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
use std::time::Duration;

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
    events: Vec<(String, String)>,
    latest: Option<Grant>,
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
            state: Mutex::new(State { client: None, client_err: String::new(), sessions: HashMap::new(), receiver: None, receiver_state: "not started (nobody has signed in)".into(), events: Vec::new(), latest: None }),
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
        let client = Arc::new(Client::new(cfg));
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
            ("GET", "/") => self.home(req),
            ("GET", "/live-status") => self.live_status(req),
            ("GET", "/login") => self.login(),
            ("GET", "/callback") => self.callback(req),
            ("POST", "/logout") => self.logout(req),
            ("POST", "/gnap/push") => self.push(req),
            _ => self.html(404, "Not found", "<h1>Not found</h1>", Vec::new()),
        }
    }

    fn static_file(&self, name: &str, content_type: &str) -> Outcome {
        match std::fs::read(self.public_dir.join(name)) {
            Ok(raw) => reply(200, vec![("content-type".into(), content_type.into()), ("cache-control".into(), "max-age=300".into())], raw),
            Err(_) => self.html(404, "Not found", "<h1>Not found</h1>", Vec::new()),
        }
    }

    fn home(&self, req: &Request) -> Outcome {
        let client = self.try_client();
        if let Some(session) = self.session(req) {
            let who = session
                .person
                .as_ref()
                .map(|person| person.email.clone().filter(|value| !value.is_empty()).or_else(|| person.name.clone().filter(|value| !value.is_empty())).unwrap_or_else(|| person.sub.clone()))
                .unwrap_or_default();
            let body = format!("<h1>Signed in</h1><p>{}</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>", escape(&who));
            return self.html(200, "Signed in", &body, Vec::new());
        }
        if client.is_none() {
            let msg = {
                let state = self.state.lock().unwrap();
                if state.client_err.is_empty() { "the key could not be read".into() } else { state.client_err.clone() }
            };
            let body = format!("<h1>GNAP CAEP RISC demo</h1><p>The GNAP client is not configured yet: {}. Generate the key at the privateKey path, then run scripts/configure_iya_sts.py.</p>", escape(&msg));
            return self.html(200, "GNAP demo", &body, Vec::new());
        }
        self.html(200, "GNAP demo", "<h1>GNAP CAEP RISC demo</h1><p><a class=\"button\" href=\"/login\">Sign in with GNAP</a></p>", Vec::new())
    }

    /// The sign-in and the Shared Signals events, for scripts/live_iya_sts.py. It carries no token
    /// and no assertion: only whether this browser is signed in, who as, the receiver's state, and
    /// the type and jti of each event received.
    fn live_status(&self, req: &Request) -> Outcome {
        let subject = self.session(req).and_then(|session| session.person).map(|person| {
            [person.preferred_username, person.email, person.name]
                .into_iter()
                .flatten()
                .find(|value| !value.is_empty())
                .unwrap_or(person.sub)
        });
        let (receiver, events) = {
            let state = self.state.lock().unwrap();
            let events: Vec<Value> = state.events.iter().map(|(kind, jti)| serde_json::json!({"type": kind, "jti": jti})).collect();
            (state.receiver_state.clone(), events)
        };
        let body = serde_json::json!({
            "signedIn": subject.is_some(),
            "subject": subject,
            "receiver": receiver,
            "events": events,
        });
        reply(200, vec![("content-type".into(), "application/json".into()), ("cache-control".into(), "no-store".into())], serde_json::to_vec(&body).unwrap_or_default())
    }

    fn remember_event(&self, event: &SignalEvent) {
        let mut state = self.state.lock().unwrap();
        state.events.push((event.event_type.clone(), event.jti.clone()));
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
        if let Some(opened) = self.unseal(cookie_value(&req.headers, "gsid")) {
            if let Some(id) = opened.get("id").and_then(|item| item.as_str()) {
                let (session, receiver) = {
                    let mut state = self.state.lock().unwrap();
                    let session = state.sessions.remove(id);
                    let receiver = state.receiver.clone();
                    (session, receiver)
                };
                if let Some(session) = session {
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
            }
        }
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
        let opened = self.unseal(cookie_value(&req.headers, "gsid"))?;
        let id = opened.get("id").and_then(|item| item.as_str())?;
        self.state.lock().unwrap().sessions.get(id).map(|record| SessionRecord { person: record.person.clone(), grant: record.grant.clone() })
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
        let page = format!(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>{}</title>\n<link rel=\"stylesheet\" href=\"/styles.css\">\n</head>\n<body>\n<main>\n{body}\n</main>\n</body>\n</html>\n",
            escape(title)
        );
        let mut headers = headers;
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-type")) {
            headers.push(("content-type".into(), "text/html; charset=utf-8".into()));
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
