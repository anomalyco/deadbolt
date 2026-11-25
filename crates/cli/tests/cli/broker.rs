//! `deadbolt run --broker`: the command's environment holds placeholders
//! and the broker's URL, never a value; requests from the command reach the
//! upstream with the real token or a real SigV4 signature; the same
//! placeholder from a process outside the run is refused.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use deadbolt_remote::sigv4::{self, AmzDate, Credentials, Scope};

use super::*;

const AWS_KEY: &str = "AKIAREALKEY000000001";
const AWS_SECRET: &str = "real/secret+key0123456789abcdefghijk";

/// A request an upstream got: its head (lines) and body.
#[derive(Clone, Debug)]
struct Got {
    head: Vec<String>,
    body: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.iter().skip(1).find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// An HTTP upstream, one request per connection, that answers 200 when
/// `check` passes and 403 otherwise.
fn upstream(check: fn(&Got) -> bool) -> (u16, Arc<Mutex<Vec<Got>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(Vec::new()));
    let log = got.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push(line.trim_end().to_string());
            }
            let mut request = Got {
                head,
                body: Vec::new(),
            };
            let length: usize = request
                .header("content-length")
                .and_then(|l| l.parse().ok())
                .unwrap_or(0);
            request.body = vec![0; length];
            reader.read_exact(&mut request.body).unwrap();
            let status = if check(&request) {
                "200 OK"
            } else {
                "403 Forbidden"
            };
            log.lock().unwrap().push(request);
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .ok();
        }
    });
    (port, got)
}

#[expect(clippy::disallowed_methods, reason = "a signature's clock")]
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Whether `got` carries a SigV4 signature by the real key.
fn real_sigv4(got: &Got) -> bool {
    let Some(authorization) = got.header("authorization") else {
        return false;
    };
    let field = |name: &str| {
        authorization
            .split([' ', ','])
            .find_map(|part| part.strip_prefix(name))
            .unwrap_or_default()
            .to_string()
    };
    let credential = field("Credential=");
    let scope: Vec<&str> = credential.split('/').collect();
    let stamp = got.header("x-amz-date").unwrap_or_default();
    let now = now();
    let Some(date) = (now - 300..now + 5)
        .map(AmzDate::from_unix)
        .find(|d| d.stamp() == stamp)
    else {
        return false;
    };
    let payload = sigv4::sha256_hex(&got.body);
    if scope.len() != 5
        || scope[0] != AWS_KEY
        || got.header("x-amz-content-sha256") != Some(&payload)
    {
        return false;
    }
    let headers: Vec<(String, String)> = field("SignedHeaders=")
        .split(';')
        .map(|n| (n.to_string(), got.header(n).unwrap_or_default().to_string()))
        .collect();
    let target = got.head[0].split(' ').nth(1).unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    assert!(query.is_empty(), "{target}");
    let signature = sigv4::sign(
        &Credentials::new(AWS_KEY, AWS_SECRET),
        &date,
        &Scope {
            region: scope[2],
            service: scope[3],
        },
        &sigv4::Request {
            method: got.head[0].split(' ').next().unwrap_or_default(),
            path,
            query: &[],
            headers: &headers,
            payload_hash: &payload,
        },
    );
    signature.signature == field("Signature=")
}

/// `NAME=value` lines, as `env` prints them.
fn env_var(env: &str, name: &str) -> String {
    env.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} isn't set: {env}"))
        .to_string()
}

/// One request from this process, outside the run; its status line.
fn request_from_outside(url: &str, token: &str) -> String {
    let rest = url.strip_prefix("http://").unwrap();
    let (host, path) = rest.split_once('/').unwrap();
    let mut stream = TcpStream::connect(host).unwrap();
    write!(
        stream,
        "GET /{path}/v1/chat HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response.lines().next().unwrap_or_default().to_string()
}

#[test]
fn a_brokered_command_holds_only_placeholders() {
    let a = Device::new();
    a.run(&["init"]);
    new(
        &a,
        &["login", "--name", "OpenAI", &format!("token={TOKEN}")],
    );
    new(
        &a,
        &[
            "login",
            "--name",
            "AWS",
            &format!("access={AWS_KEY}"),
            &format!("secret={AWS_SECRET}"),
        ],
    );
    let (api, api_got) =
        upstream(|got| got.header("authorization") == Some(&*format!("Bearer {TOKEN}")));
    let (s3, s3_got) = upstream(real_sigv4);
    let (ready, go) = (a.path("ready"), a.path("go"));
    let dir = a.path("").display().to_string();
    let script = format!(
        r#"
        cd '{dir}'
        env > env.txt
        curl -s --noproxy '*' -o /dev/null -w '%{{http_code}}' -H "Authorization: Bearer $OPENAI_API_KEY" -d '{{}}' "$OPENAI_BASE_URL/v1/chat" > chat.txt
        curl -s --noproxy '*' -o /dev/null -w '%{{http_code}}' -H "Authorization: Bearer $OPENAI_API_KEY" "$OPENAI_BASE_URL/admin" > admin.txt
        curl -s --noproxy '*' --path-as-is -o /dev/null -w '%{{http_code}}' -H "Authorization: Bearer $OPENAI_API_KEY" "$DEADBOLT_BROKER_URL/openai/v1/../admin" > dots.txt
        curl -s --noproxy '*' -o /dev/null -w '%{{http_code}}' --aws-sigv4 'aws:amz:us-east-1:s3' --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" -X PUT --data-binary 'hello world' "$AWS_ENDPOINT_URL/bucket/key.txt" > s3.txt
        touch '{}'
        while [ ! -e '{}' ]; do sleep 0.05; done
        "#,
        ready.display(),
        go.display(),
    );
    let mut run = a
        .cmd(&[
            "run",
            "--broker",
            "--route",
            &format!("openai=http://127.0.0.1:{api}/v1,bearer=deadbolt://OpenAI/token,env=OPENAI_API_KEY,base-env=OPENAI_BASE_URL,method=POST,prefix=/v1"),
            "--route",
            &format!("s3=http://127.0.0.1:{s3},sigv4=us-east-1/s3,access-key=deadbolt://AWS/access,secret-key=deadbolt://AWS/secret,prefix=/bucket"),
            "--",
            "sh",
            "-c",
            &script,
        ])
        .env("AWS_SESSION_TOKEN", "an-inherited-token")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    eventually("the brokered command to finish its requests", || {
        ready.exists()
    });

    let env = std::fs::read_to_string(a.path("env.txt")).unwrap();
    for secret in [TOKEN, AWS_KEY, AWS_SECRET, "an-inherited-token"] {
        assert!(
            !env.contains(secret),
            "the command's environment holds a secret"
        );
    }
    let placeholder = env_var(&env, "OPENAI_API_KEY");
    assert!(
        placeholder.starts_with("db_ph_") && placeholder.len() == 38,
        "{placeholder}"
    );
    assert!(env_var(&env, "AWS_ACCESS_KEY_ID").starts_with("db_ph_"));
    assert!(env_var(&env, "AWS_SECRET_ACCESS_KEY").starts_with("db_ph_"));
    let base = env_var(&env, "OPENAI_BASE_URL");
    assert!(
        base.starts_with("http://127.0.0.1:") && base.ends_with("/openai"),
        "{base}"
    );
    assert!(env_var(&env, "AWS_ENDPOINT_URL").ends_with("/s3"));
    assert!(!env.contains("AWS_SESSION_TOKEN="));

    let status = |name: &str| std::fs::read_to_string(a.path(name)).unwrap();
    assert_eq!(status("chat.txt"), "200");
    assert_eq!(status("admin.txt"), "403");
    assert!(
        ["400", "403"].contains(&status("dots.txt").as_str()),
        "{}",
        status("dots.txt")
    );
    assert_eq!(status("s3.txt"), "200");
    let api_got = api_got.lock().unwrap().clone();
    assert_eq!(api_got.len(), 1);
    assert_eq!(api_got[0].head[0], "POST /v1/v1/chat HTTP/1.1");
    let s3_got = s3_got.lock().unwrap().clone();
    assert_eq!(s3_got.len(), 1);
    assert_eq!(s3_got[0].body, b"hello world");
    assert!(s3_got[0].header("x-amz-security-token").is_none());

    // The same placeholder, from a process outside the run, gets nothing.
    let outside = request_from_outside(&base, &placeholder);
    assert!(outside.contains(" 403 "), "{outside}");
    assert_eq!(api_got.len(), 1);

    std::fs::write(&go, "").unwrap();
    assert!(wait(&mut run, Duration::from_secs(30)).success());
    let output = run.wait_with_output().unwrap();
    let printed = [output.stdout, output.stderr].concat();
    assert!(!String::from_utf8_lossy(&printed).contains(TOKEN));

    // The broker went with the run: its port no longer answers.
    let port = base
        .trim_start_matches("http://127.0.0.1:")
        .split('/')
        .next()
        .unwrap();
    eventually("the broker to stop", || {
        TcpStream::connect(format!("127.0.0.1:{port}")).is_err()
    });
}
