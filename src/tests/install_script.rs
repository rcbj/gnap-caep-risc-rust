// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! `scripts/configure_iya_sts.py`'s attribute-protected setup, run with
//! python3 against a recording stand-in for `/admin-api` (no iya-sts):
//! the demo policy's rules, defining attr1 with its own admin:security
//! token, saying what to do only when attr1 cannot be defined and is not,
//! and the application's policy rewritten only while it is the script's own.

use serde_json::Value;
use std::process::Command;

/// Runs `body` (Python, with the script loaded as `mod`, `json` and a
/// `Recorder` stand-in for `api`) and answers what it printed, as JSON lines
/// and text.
fn run(body: &str, tag: &str) -> (String, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("gnap-install-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prelude = r#"import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("configure_iya_sts", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
DIR = sys.argv[2]

class Recorder:
    """Answers each /admin-api path from `answers` (a dict, or a callable),
    and records (path, body, security) for every call."""
    def __init__(self, answers):
        self.answers = answers
        self.calls = []
    def __call__(self, path, body=None, method="POST", security=False):
        self.calls.append({"path": path, "body": body, "method": method, "security": security})
        key = path.split("?")[0]
        answer = self.answers.get(key, {"status": 200, "body": {"ok": True}})
        if callable(answer):
            answer = answer(body)
        if isinstance(answer, Exception):
            raise answer
        return answer
"#;
    let script = format!("{prelude}\n{body}");
    let configure = format!("{}/scripts/configure_iya_sts.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3").arg("-c").arg(&script).arg(&configure).arg(&dir).output().unwrap();
    assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (String::from_utf8_lossy(&out.stdout).into_owned(), dir)
}

fn last_json(printed: &str) -> Value {
    serde_json::from_str(printed.lines().last().unwrap_or("null")).unwrap()
}

#[test]
fn the_demo_policy_permits_attribute_protected_on_attr1_only() {
    let (printed, dir) = run(r#"print(json.dumps({"alfa": mod.orders_policy(), "locked": mod.orders_policy("gnapdemolocked", "deny"), "own": list(mod.OWN_POLICY_IDS)}))"#, "policy");
    let _ = std::fs::remove_dir_all(&dir);
    let v = last_json(&printed);
    let alfa = v["alfa"].as_str().unwrap();
    assert!(alfa.contains(r#"attribute attr1 { category = subjectCat id = "urn:sts:xacml:attribute:attr1" type = string }"#), "{alfa}");
    let rule = &alfa[alfa.find("rule readAttributeProtected").expect("the rule")..alfa.find("rule otherwise").unwrap()];
    for clause in ["permit", r#"target clause act == "read""#, r#"target clause rtype == "attribute-protected""#, r#"target clause attr1 == "abc123""#] {
        assert!(rule.contains(clause), "{clause} in {rule}");
    }
    assert!(alfa.find("rule readOrder").unwrap() < alfa.find("rule readAttributeProtected").unwrap(), "first applicable: the order rule keeps its place");
    assert!(alfa.contains(r#"id = "urn:example:gnapdemo-orders""#));
    assert_eq!(v["own"], serde_json::json!(["urn:example:gnapdemo-orders"]), "the PolicyId the script writes is its own");
    assert!(!v["locked"].as_str().unwrap().contains("urn:example:gnapdemo-orders"), "the live test's locked policy is not the script's own");
}

#[test]
fn attr1_is_defined_with_an_admin_security_token_and_the_value_set() {
    let (printed, dir) = run(r#"
api = Recorder({})
held = mod.set_test_attribute(api, "gnap-demo-user")
print(json.dumps({"held": held, "calls": api.calls}))
"#, "defined");
    let _ = std::fs::remove_dir_all(&dir);
    let v = last_json(&printed);
    assert_eq!(v["held"], true);
    let calls = v["calls"].as_array().unwrap();
    assert_eq!(calls[0]["path"], "/policies/define-person-attribute");
    assert_eq!(calls[0]["security"], true, "only the definition carries the admin:security token");
    assert_eq!(calls[0]["body"]["name"], "attr1");
    assert_eq!(calls[1]["path"], "/users/set-attribute");
    assert_eq!(calls[1]["security"], false);
    assert_eq!(calls[1]["body"], serde_json::json!({"user": "gnap-demo-user", "attribute": "attr1", "value": "abc123"}));
    assert!(printed.contains("gnap-demo-user has attr1=abc123"), "{printed}");
}

#[test]
fn the_operator_is_told_what_to_do_only_when_attr1_cannot_be_defined_and_is_not() {
    // Refused (the client was taken out of SECURITY_ADMIN), but attr1 is
    // defined already: the value is set, and nothing is asked of anybody.
    let (printed, dir) = run(r#"
refusal = RuntimeError('POST x answered 403: {"errors": ["Only a Security Administrator may make this change"]}')
api = Recorder({"/policies/define-person-attribute": refusal})
print(json.dumps({"held": mod.set_test_attribute(api, "u1")}))
"#, "refused-defined");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(last_json(&printed)["held"], true);
    assert!(!printed.contains("Security Administrator"), "{printed}");

    // Refused, and attr1 is not defined: now the operator is told.
    let (printed, dir) = run(r#"
api = Recorder({
    "/policies/define-person-attribute": {"status": 403, "body": {"ok": False, "errors": ["Only a Security Administrator may make this change"]}},
    "/users/set-attribute": {"status": 400, "body": {"ok": False, "errors": ["attr1 is not an attribute of this realm"]}},
})
print(json.dumps({"held": mod.set_test_attribute(api, "u1")}))
"#, "refused-undefined");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(last_json(&printed)["held"], false);
    assert!(printed.contains("The custom attribute attr1 is not defined, and this credential cannot define it"), "{printed}");
    assert!(printed.contains("Custom") && printed.contains("run\nthis script again"), "{printed}");

    // Already defined (an earlier run): no message, the value is set.
    let (printed, dir) = run(r#"
api = Recorder({"/policies/define-person-attribute": {"status": 400, "body": {"ok": False, "errors": ["attr1 already exists"]}}})
print(json.dumps({"held": mod.set_test_attribute(api, "u1")}))
"#, "exists");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(last_json(&printed)["held"], true);

    // Any other refusal of the definition stops the script.
    let (printed, dir) = run(r#"
api = Recorder({"/policies/define-person-attribute": {"status": 500, "body": {"ok": False, "errors": ["broken"]}}})
try:
    mod.set_test_attribute(api, "u1")
    print(json.dumps({"raised": False}))
except RuntimeError as err:
    print(json.dumps({"raised": True, "why": str(err)}))
"#, "broken");
    let _ = std::fs::remove_dir_all(&dir);
    let v = last_json(&printed);
    assert_eq!(v["raised"], true);
    assert!(v["why"].as_str().unwrap().contains("broken"));
}

#[test]
fn the_applications_policy_is_rewritten_only_while_it_is_the_scripts_own() {
    // `enforced` with a PolicyId: the script's own is written again with the
    // current rules; another is an administrator's, and left alone.
    let body = r#"
import pathlib
def page(policy_id, enforced=True):
    return {"status": 200, "body": {"page": {"fga": {"enforced": enforced, "policy": {"name": "gnap-caep-risc-demo-policy", "policyId": policy_id}}, "attributes": {}}}}
config = pathlib.Path(DIR) / "gnap.json"
config.write_text(json.dumps({"grantEndpoint": "https://sts.example/gnap", "application": "gnap-caep-risc-demo"}))
out = {}
for case, answer in [("own", page("urn:example:gnapdemo-orders")), ("other", page("urn:example:theirs")), ("none", page("", False))]:
    api = Recorder({"/applications": answer, "/users": {"status": 200, "body": {"known": True}}})
    mod.setup_pep(api, {"application": "gnap-caep-risc-demo"}, str(config), "pep-gnap-demo", "local")
    out[case] = [c for c in api.calls if c["path"] in ("/xacml/import-alfa", "/applications/fga-enable", "/applications/fga-create-policy")]
print(json.dumps(out))
"#;
    let (printed, dir) = run(body, "own-policy");
    let section: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("gnap.json")).unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let v = last_json(&printed);
    let own = v["own"].as_array().unwrap();
    assert_eq!(own.len(), 1, "the script's own policy: only written again, {own:?}");
    assert_eq!(own[0]["path"], "/xacml/import-alfa");
    assert!(own[0]["body"]["alfa"].as_str().unwrap().contains("readAttributeProtected"), "with the current rules");
    assert!(printed.contains("it now holds the current version"), "{printed}");
    assert_eq!(v["other"], serde_json::json!([]), "an administrator's policy is left alone");
    assert!(printed.contains("already enforces a policy of its own (urn:example:theirs)"), "{printed}");
    let fresh: Vec<&str> = v["none"].as_array().unwrap().iter().filter_map(|c| c["path"].as_str()).collect();
    assert_eq!(fresh, ["/applications/fga-create-policy", "/xacml/import-alfa", "/applications/fga-enable"], "none enforced yet: made, written, enforced");
    assert_eq!(section["pep"]["mode"], "local");
}
