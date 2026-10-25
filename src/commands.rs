//! The Linear commands agents use: issues, comments, files and attachments.
//! Each returns the JSON value `lin` prints.

use std::path::Path;

use serde_json::{Value, json};

use crate::api::Client;
use crate::error::{Error, Result};

const ISSUE_FIELDS: &str = "
fragment IssueFields on Issue {
  id identifier title description url priority priorityLabel createdAt updatedAt
  state { name type }
  assignee { id name }
  team { id key name }
  project { id name }
  parent { id identifier title }
  labels { nodes { name } }
  relations { nodes { type relatedIssue { identifier } } }
  inverseRelations { nodes { type issue { identifier } } }
}";

fn with_fields(op: &str) -> String {
    format!("{op}\n{ISSUE_FIELDS}")
}

/// Flatten Linear's connection shapes into what an agent needs: label names
/// and lists of identifiers per relation type.
fn shape_issue(mut issue: Value) -> Value {
    let Some(obj) = issue.as_object_mut() else {
        return issue;
    };
    let names = |v: Option<Value>| -> Vec<Value> {
        v.and_then(|l| l["nodes"].as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .map(|n| n["name"].clone())
            .collect()
    };
    let labels = names(obj.remove("labels"));
    obj.insert("labels".into(), Value::Array(labels));

    // `relations` are from this issue's side, `inverseRelations` from the
    // other issue's, so "blocks" flips to "blocked_by" there.
    let mut relations = serde_json::Map::new();
    for (key, other, inverse) in [
        ("relations", "relatedIssue", false),
        ("inverseRelations", "issue", true),
    ] {
        let nodes = obj
            .remove(key)
            .and_then(|r| r["nodes"].as_array().cloned())
            .unwrap_or_default();
        for n in nodes {
            let name = match (n["type"].as_str().unwrap_or("related"), inverse) {
                ("blocks", false) => "blocks",
                ("blocks", true) => "blocked_by",
                ("duplicate", false) => "duplicates",
                ("duplicate", true) => "duplicated_by",
                (other, _) => other,
            };
            if let Value::Array(list) = relations
                .entry(name.to_string())
                .or_insert_with(|| json!([]))
            {
                list.push(n[other]["identifier"].clone());
            }
        }
    }
    obj.insert("relations".into(), Value::Object(relations));
    issue
}

fn mutation_result<'a>(data: &'a Value, field: &str) -> Result<&'a Value> {
    let payload = &data[field];
    if payload["success"].as_bool() == Some(false) {
        return Err(Error::Api {
            message: format!("{field} reported success: false"),
            details: payload.clone(),
        });
    }
    Ok(payload)
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Turn an identifier like `ENG-123` into the issue's UUID, which mutations
/// that take an `issueId` expect.
fn issue_uuid(client: &Client, id: &str) -> Result<String> {
    if is_uuid(id) {
        return Ok(id.to_string());
    }
    let data = client.graphql(
        "query($id: String!) { issue(id: $id) { id } }",
        json!({ "id": id }),
    )?;
    data["issue"]["id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| Error::Usage(format!("issue {id} not found")))
}

pub fn issue_read(client: &Client, id: &str) -> Result<Value> {
    let data = client.graphql(
        &with_fields("query($id: String!) { issue(id: $id) { ...IssueFields } }"),
        json!({ "id": id }),
    )?;
    Ok(shape_issue(data["issue"].clone()))
}

pub struct IssueChanges {
    pub title: Option<String>,
    pub description: Option<String>,
}

pub fn issue_update(client: &Client, id: &str, changes: IssueChanges) -> Result<Value> {
    let mut input = json!({});
    if let Some(t) = changes.title {
        input["title"] = json!(t);
    }
    if let Some(d) = changes.description {
        input["description"] = json!(d);
    }
    if input.as_object().is_some_and(|o| o.is_empty()) {
        return Err(Error::Usage(
            "nothing to update: pass --title and/or --description".into(),
        ));
    }
    let uuid = issue_uuid(client, id)?;
    let data = client.graphql(
        &with_fields(
            "mutation($id: String!, $input: IssueUpdateInput!) {
               issueUpdate(id: $id, input: $input) { success issue { ...IssueFields } }
             }",
        ),
        json!({ "id": uuid, "input": input }),
    )?;
    let payload = mutation_result(&data, "issueUpdate")?;
    Ok(shape_issue(payload["issue"].clone()))
}

pub struct NewIssue {
    pub title: String,
    pub description: Option<String>,
    pub team: Option<String>,
    pub parent: Option<String>,
    pub blocks: Vec<String>,
}

fn team_id_for_key(client: &Client, key: &str) -> Result<String> {
    let data = client.graphql(
        "query($key: String!) { teams(filter: { key: { eqIgnoreCase: $key } }) { nodes { id } } }",
        json!({ "key": key }),
    )?;
    data["teams"]["nodes"][0]["id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| Error::Usage(format!("no team with key {key}")))
}

pub fn issue_create(client: &Client, new: NewIssue) -> Result<Value> {
    let mut input = json!({ "title": new.title });
    if let Some(d) = new.description {
        input["description"] = json!(d);
    }
    match (&new.team, &new.parent) {
        (Some(key), _) => input["teamId"] = json!(team_id_for_key(client, key)?),
        (None, None) => {
            return Err(Error::Usage(
                "pass --team, or --parent-ticket to use the parent's team".into(),
            ));
        }
        (None, Some(_)) => {}
    }
    if let Some(parent) = &new.parent {
        let data = client.graphql(
            "query($id: String!) { issue(id: $id) { id team { id } } }",
            json!({ "id": parent }),
        )?;
        let p = &data["issue"];
        input["parentId"] = p["id"].clone();
        if input.get("teamId").is_none() {
            input["teamId"] = p["team"]["id"].clone();
        }
    }
    // Resolve blocked issues before creating anything, so a typo fails cleanly.
    let blocked: Vec<String> = new
        .blocks
        .iter()
        .map(|b| issue_uuid(client, b))
        .collect::<Result<_>>()?;

    let data = client.graphql(
        &with_fields(
            "mutation($input: IssueCreateInput!) {
               issueCreate(input: $input) { success issue { ...IssueFields } }
             }",
        ),
        json!({ "input": input }),
    )?;
    let issue = mutation_result(&data, "issueCreate")?["issue"].clone();
    let new_id = issue["id"].clone();

    for related in &blocked {
        let data = client.graphql(
            "mutation($input: IssueRelationCreateInput!) { issueRelationCreate(input: $input) { success } }",
            json!({ "input": { "issueId": new_id, "relatedIssueId": related, "type": "blocks" } }),
        )?;
        mutation_result(&data, "issueRelationCreate")?;
    }
    let mut out = shape_issue(issue);
    if !new.blocks.is_empty() {
        out["relations"]["blocks"] = json!(new.blocks);
    }
    Ok(out)
}

/// Start a new top-level comment thread on an issue.
pub fn issue_discuss(client: &Client, id: &str, body: &str) -> Result<Value> {
    let uuid = issue_uuid(client, id)?;
    let data = client.graphql(
        "mutation($input: CommentCreateInput!) {
           commentCreate(input: $input) { success comment { id url body createdAt } }
         }",
        json!({ "input": { "issueId": uuid, "body": body } }),
    )?;
    Ok(mutation_result(&data, "commentCreate")?["comment"].clone())
}

pub struct NewAttachment {
    pub url: String,
    pub title: String,
    pub subtitle: Option<String>,
}

pub fn attachment_create(client: &Client, id: &str, a: NewAttachment) -> Result<Value> {
    let uuid = issue_uuid(client, id)?;
    let mut input = json!({ "issueId": uuid, "url": a.url, "title": a.title });
    if let Some(s) = a.subtitle {
        input["subtitle"] = json!(s);
    }
    let data = client.graphql(
        "mutation($input: AttachmentCreateInput!) {
           attachmentCreate(input: $input) { success attachment { id url title subtitle } }
         }",
        json!({ "input": input }),
    )?;
    Ok(mutation_result(&data, "attachmentCreate")?["attachment"].clone())
}

pub fn content_type_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        Some("txt" | "log") => "text/plain",
        Some("md") => "text/markdown",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

/// Upload a file to Linear's storage and return its asset URL, plus a
/// ready-to-paste markdown snippet.
pub fn file_upload(client: &Client, path: &Path, content_type: Option<String>) -> Result<Value> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Usage(format!("can't read {}: {e}", path.display())))?;
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Usage(format!("bad file name: {}", path.display())))?
        .to_string();
    let content_type = content_type.unwrap_or_else(|| content_type_for(path).to_string());

    let data = client.graphql(
        "mutation($contentType: String!, $filename: String!, $size: Int!) {
           fileUpload(contentType: $contentType, filename: $filename, size: $size) {
             success uploadFile { uploadUrl assetUrl headers { key value } }
           }
         }",
        json!({ "contentType": content_type, "filename": filename, "size": bytes.len() }),
    )?;
    let upload = &mutation_result(&data, "fileUpload")?["uploadFile"];
    let upload_url = upload["uploadUrl"].as_str().ok_or_else(|| Error::Api {
        message: "fileUpload returned no uploadUrl".into(),
        details: upload.clone(),
    })?;

    let mut headers = vec![
        ("Content-Type".to_string(), content_type.clone()),
        (
            "Cache-Control".to_string(),
            "public, max-age=31536000".to_string(),
        ),
    ];
    for h in upload["headers"].as_array().into_iter().flatten() {
        if let (Some(k), Some(v)) = (h["key"].as_str(), h["value"].as_str()) {
            headers.push((k.to_string(), v.to_string()));
        }
    }
    let status = client.put(upload_url, &headers, &bytes)?;
    if !(200..300).contains(&status) {
        return Err(Error::Http(format!(
            "file upload PUT returned HTTP {status}"
        )));
    }

    let asset_url = upload["assetUrl"].clone();
    let url = asset_url.as_str().unwrap_or_default();
    let markdown = if content_type.starts_with("image/") {
        format!("![{filename}]({url})")
    } else {
        format!("[{filename}]({url})")
    };
    Ok(json!({
        "asset_url": asset_url,
        "filename": filename,
        "content_type": content_type,
        "size": bytes.len(),
        "markdown": markdown,
    }))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;
    use crate::api::Transport;

    /// A recorded upload PUT: URL, headers and body length.
    type Put = (String, Vec<(String, String)>, usize);

    /// Replays canned Linear responses in order and records every request.
    #[derive(Default)]
    struct Fake {
        responses: RefCell<VecDeque<Value>>,
        requests: RefCell<Vec<Value>>,
        puts: RefCell<Vec<Put>>,
        put_status: u16,
    }

    impl Transport for Rc<Fake> {
        fn graphql(&self, body: &Value) -> Result<(u16, Value)> {
            self.requests.borrow_mut().push(body.clone());
            let resp = self
                .responses
                .borrow_mut()
                .pop_front()
                .expect("unexpected extra GraphQL request");
            Ok((200, resp))
        }
        fn put(&self, url: &str, headers: &[(String, String)], bytes: &[u8]) -> Result<u16> {
            self.puts
                .borrow_mut()
                .push((url.to_string(), headers.to_vec(), bytes.len()));
            Ok(self.put_status)
        }
    }

    fn client(responses: Vec<Value>) -> (Client, Rc<Fake>) {
        let fake = Rc::new(Fake {
            responses: RefCell::new(responses.into()),
            put_status: 200,
            ..Default::default()
        });
        (Client::with_transport(fake.clone()), fake)
    }

    const UUID_A: &str = "4a0c1b2e-1111-4c3d-9e8f-0123456789ab";
    const UUID_B: &str = "5b1d2c3f-2222-4d4e-8f90-123456789abc";

    fn issue_fixture() -> Value {
        json!({
            "id": UUID_A, "identifier": "ENG-1", "title": "Fix login",
            "description": "Steps...", "url": "https://linear.app/acme/issue/ENG-1",
            "priority": 2, "priorityLabel": "High",
            "createdAt": "2026-10-01T00:00:00.000Z", "updatedAt": "2026-10-02T00:00:00.000Z",
            "state": { "name": "In Progress", "type": "started" },
            "assignee": { "id": "u1", "name": "Jay" },
            "team": { "id": "t1", "key": "ENG", "name": "Engineering" },
            "project": null,
            "parent": { "id": UUID_B, "identifier": "ENG-0", "title": "Epic" },
            "labels": { "nodes": [{ "name": "bug" }, { "name": "auth" }] },
            "relations": { "nodes": [
                { "type": "blocks", "relatedIssue": { "identifier": "ENG-2" } },
                { "type": "related", "relatedIssue": { "identifier": "ENG-3" } }
            ] },
            "inverseRelations": { "nodes": [
                { "type": "blocks", "issue": { "identifier": "ENG-9" } },
                { "type": "duplicate", "issue": { "identifier": "ENG-8" } }
            ] }
        })
    }

    fn vars(fake: &Fake, i: usize) -> Value {
        fake.requests.borrow()[i]["variables"].clone()
    }

    fn query(fake: &Fake, i: usize) -> String {
        fake.requests.borrow()[i]["query"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn read_flattens_labels_and_relations() {
        let (c, fake) = client(vec![json!({ "data": { "issue": issue_fixture() } })]);
        let v = issue_read(&c, "ENG-1").unwrap();
        assert_eq!(vars(&fake, 0)["id"], "ENG-1");
        assert_eq!(v["labels"], json!(["bug", "auth"]));
        assert_eq!(
            v["relations"],
            json!({
                "blocks": ["ENG-2"], "related": ["ENG-3"],
                "blocked_by": ["ENG-9"], "duplicated_by": ["ENG-8"]
            })
        );
        assert_eq!(v["parent"]["identifier"], "ENG-0");
        assert!(query(&fake, 0).contains("fragment IssueFields on Issue"));
    }

    #[test]
    fn read_not_found_is_an_api_error() {
        let (c, _) = client(vec![json!({
            "errors": [{ "message": "Entity not found: Issue", "extensions": { "code": "ENTITY_NOT_FOUND" } }],
            "data": null
        })]);
        let e = issue_read(&c, "ENG-404").unwrap_err();
        assert_eq!(e.code(), "api_error");
        assert!(e.to_string().contains("Entity not found"));
    }

    #[test]
    fn update_replaces_description_by_uuid() {
        let (c, fake) = client(vec![
            json!({ "data": { "issue": { "id": UUID_A } } }),
            json!({ "data": { "issueUpdate": { "success": true, "issue": issue_fixture() } } }),
        ]);
        let v = issue_update(
            &c,
            "ENG-1",
            IssueChanges {
                title: None,
                description: Some("New body".into()),
            },
        )
        .unwrap();
        assert_eq!(
            vars(&fake, 1),
            json!({ "id": UUID_A, "input": { "description": "New body" } })
        );
        assert_eq!(v["identifier"], "ENG-1");
    }

    #[test]
    fn update_with_nothing_makes_no_requests() {
        let (c, fake) = client(vec![]);
        let e = issue_update(
            &c,
            "ENG-1",
            IssueChanges {
                title: None,
                description: None,
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "usage_error");
        assert!(fake.requests.borrow().is_empty());
    }

    #[test]
    fn uuid_skips_lookup() {
        let (c, fake) = client(vec![json!({
            "data": { "commentCreate": { "success": true, "comment": { "id": "c1", "url": "u", "body": "hi", "createdAt": "t" } } }
        })]);
        let v = issue_discuss(&c, UUID_A, "hi").unwrap();
        assert_eq!(fake.requests.borrow().len(), 1);
        assert_eq!(
            vars(&fake, 0)["input"],
            json!({ "issueId": UUID_A, "body": "hi" })
        );
        assert_eq!(v["id"], "c1");
    }

    #[test]
    fn create_with_parent_and_blocks() {
        let mut created = issue_fixture();
        created["id"] = json!("new-id");
        created["identifier"] = json!("ENG-10");
        created["relations"] = json!({ "nodes": [] });
        created["inverseRelations"] = json!({ "nodes": [] });
        let (c, fake) = client(vec![
            // parent lookup
            json!({ "data": { "issue": { "id": UUID_B, "team": { "id": "t1" } } } }),
            // --blocks ENG-2 resolution
            json!({ "data": { "issue": { "id": UUID_A } } }),
            json!({ "data": { "issueCreate": { "success": true, "issue": created } } }),
            json!({ "data": { "issueRelationCreate": { "success": true } } }),
        ]);
        let v = issue_create(
            &c,
            NewIssue {
                title: "Sub task".into(),
                description: Some("Details".into()),
                team: None,
                parent: Some("ENG-0".into()),
                blocks: vec!["ENG-2".into()],
            },
        )
        .unwrap();
        assert_eq!(
            vars(&fake, 2)["input"],
            json!({ "title": "Sub task", "description": "Details", "parentId": UUID_B, "teamId": "t1" })
        );
        assert_eq!(
            vars(&fake, 3)["input"],
            json!({ "issueId": "new-id", "relatedIssueId": UUID_A, "type": "blocks" })
        );
        assert_eq!(v["identifier"], "ENG-10");
        assert_eq!(v["relations"]["blocks"], json!(["ENG-2"]));
    }

    #[test]
    fn create_with_team_key() {
        let (c, fake) = client(vec![
            json!({ "data": { "teams": { "nodes": [{ "id": "t9" }] } } }),
            json!({ "data": { "issueCreate": { "success": true, "issue": issue_fixture() } } }),
        ]);
        issue_create(
            &c,
            NewIssue {
                title: "T".into(),
                description: None,
                team: Some("eng".into()),
                parent: None,
                blocks: vec![],
            },
        )
        .unwrap();
        assert_eq!(vars(&fake, 0), json!({ "key": "eng" }));
        assert_eq!(
            vars(&fake, 1)["input"],
            json!({ "title": "T", "teamId": "t9" })
        );
    }

    #[test]
    fn create_needs_team_or_parent() {
        let (c, fake) = client(vec![]);
        let e = issue_create(
            &c,
            NewIssue {
                title: "T".into(),
                description: None,
                team: None,
                parent: None,
                blocks: vec![],
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "usage_error");
        assert!(fake.requests.borrow().is_empty());
    }

    #[test]
    fn unknown_blocked_issue_fails_before_create() {
        let (c, fake) = client(vec![
            json!({ "data": { "teams": { "nodes": [{ "id": "t1" }] } } }),
            json!({ "errors": [{ "message": "Entity not found: Issue" }], "data": null }),
        ]);
        let e = issue_create(
            &c,
            NewIssue {
                title: "T".into(),
                description: None,
                team: Some("ENG".into()),
                parent: None,
                blocks: vec!["ENG-999".into()],
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), "api_error");
        assert_eq!(fake.requests.borrow().len(), 2, "issueCreate must not run");
    }

    #[test]
    fn mutation_success_false_is_an_error() {
        let (c, _) = client(vec![json!({
            "data": { "attachmentCreate": { "success": false, "attachment": null } }
        })]);
        let e = attachment_create(
            &c,
            UUID_A,
            NewAttachment {
                url: "https://x".into(),
                title: "X".into(),
                subtitle: None,
            },
        )
        .unwrap_err();
        assert!(e.to_string().contains("success: false"));
    }

    #[test]
    fn attachment_create_sends_input() {
        let (c, fake) = client(vec![json!({
            "data": { "attachmentCreate": { "success": true, "attachment": {
                "id": "a1", "url": "https://github.com/o/r/pull/1", "title": "PR #1", "subtitle": "open"
            } } }
        })]);
        let v = attachment_create(
            &c,
            UUID_A,
            NewAttachment {
                url: "https://github.com/o/r/pull/1".into(),
                title: "PR #1".into(),
                subtitle: Some("open".into()),
            },
        )
        .unwrap();
        assert_eq!(
            vars(&fake, 0)["input"],
            json!({ "issueId": UUID_A, "url": "https://github.com/o/r/pull/1", "title": "PR #1", "subtitle": "open" })
        );
        assert_eq!(v["id"], "a1");
    }

    fn temp_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn upload_puts_bytes_with_signed_headers() {
        let path = temp_file("shot.png", &[0u8; 1234]);
        let (c, fake) = client(vec![json!({
            "data": { "fileUpload": { "success": true, "uploadFile": {
                "uploadUrl": "https://storage.example/put?sig=abc",
                "assetUrl": "https://uploads.linear.app/o/a/shot.png",
                "headers": [{ "key": "x-goog-meta-foo", "value": "bar" }]
            } } }
        })]);
        let v = file_upload(&c, &path, None).unwrap();
        assert_eq!(
            vars(&fake, 0),
            json!({ "contentType": "image/png", "filename": "shot.png", "size": 1234 })
        );
        let puts = fake.puts.borrow();
        assert_eq!(puts[0].0, "https://storage.example/put?sig=abc");
        assert_eq!(puts[0].2, 1234);
        assert!(
            puts[0]
                .1
                .contains(&("Content-Type".into(), "image/png".into()))
        );
        assert!(
            puts[0]
                .1
                .contains(&("x-goog-meta-foo".into(), "bar".into()))
        );
        assert_eq!(v["asset_url"], "https://uploads.linear.app/o/a/shot.png");
        assert_eq!(
            v["markdown"],
            "![shot.png](https://uploads.linear.app/o/a/shot.png)"
        );
    }

    #[test]
    fn upload_put_failure_is_reported() {
        let path = temp_file("notes.txt", b"hello");
        let fake = Rc::new(Fake {
            responses: RefCell::new(
                vec![
                    json!({ "data": { "fileUpload": { "success": true, "uploadFile": {
                    "uploadUrl": "https://s/put", "assetUrl": "https://a/notes.txt", "headers": []
                } } } }),
                ]
                .into(),
            ),
            put_status: 403,
            ..Default::default()
        });
        let c = Client::with_transport(fake.clone());
        let e = file_upload(&c, &path, None).unwrap_err();
        assert!(e.to_string().contains("403"));
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type_for(Path::new("a.PNG")), "image/png");
        assert_eq!(content_type_for(Path::new("a.jpeg")), "image/jpeg");
        assert_eq!(content_type_for(Path::new("a")), "application/octet-stream");
    }

    #[test]
    fn uuid_detection() {
        assert!(is_uuid(UUID_A));
        assert!(!is_uuid("ENG-123"));
        assert!(!is_uuid("4a0c1b2e-1111-4c3d-9e8f-0123456789aZ"));
    }
}
