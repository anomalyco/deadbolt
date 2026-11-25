# deadbolt broker

`deadbolt run --broker` lets an unmodified HTTP or AWS client use a secret
without ever holding it. The command gets a placeholder and a loopback URL.
A broker process holds the real value and swaps it in on the way out.

```sh
deadbolt run --broker \
  --route 'openai=https://api.openai.com/v1,bearer=deadbolt://AI/OpenAI/key,env=OPENAI_API_KEY,base-env=OPENAI_BASE_URL,method=POST,method=GET,prefix=/chat,prefix=/models' \
  --route 's3=https://s3.us-east-1.amazonaws.com,sigv4=us-east-1/s3,access-key=deadbolt://AWS/prod/access,secret-key=deadbolt://AWS/prod/secret,prefix=/my-bucket' \
  -- sh -c 'python app.py && aws s3 cp out.json s3://my-bucket/'
```

The command's environment then holds:

| variable | value |
|---|---|
| `OPENAI_API_KEY` | `db_ph_<32 hex>`, fresh for the run |
| `OPENAI_BASE_URL` | `http://127.0.0.1:<port>/openai` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | placeholders |
| `AWS_ENDPOINT_URL` | `http://127.0.0.1:<port>/s3` |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | the route's region, if unset |
| `DEADBOLT_BROKER_URL` | `http://127.0.0.1:<port>` |

`AWS_SESSION_TOKEN` and `AWS_SECURITY_TOKEN` are removed. `ps eww` and
`/proc/<pid>/environ` show only these values. Without `--broker`,
`deadbolt run` behaves as before.

## Route keys

`--route ALIAS=URL[,KEY=VALUE...]`. A request to `<broker>/ALIAS/rest` goes
to `URL/rest`. The upstream host always comes from the route, never from
the request. `URL` must use `https`; plain `http` is allowed only for a
loopback host.

| key | meaning |
|---|---|
| `bearer=REF` and `env=NAME` | The caller sends `Authorization: Bearer <placeholder>`; upstream gets the token. |
| `header=NAME` | The same, in a bare header such as `x-api-key` (Anthropic). |
| `sigv4=REGION/SERVICE` | AWS SigV4, with `access-key=REF`, `secret-key=REF` and optionally `session-token=REF`. |
| `base-env=NAME` | The variable for the route's URL. SigV4 routes default to `AWS_ENDPOINT_URL`. |
| `method=M` | Allowed methods (repeat the key). The default is GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS. |
| `prefix=P` | Allowed paths on segment boundaries (repeatable). |
| `glob=G` | Allowed paths by glob: `*` matches within a segment, `**` matches any number of segments (repeatable). |
| `max-body=BYTES` | The request body limit (default 10 MiB). |

## How it works

1. `deadbolt run` hardens itself the way the broker does (step 3) before
   it resolves every reference. It then registers itself with the daemon
   (taint), so the broker and the command both run inside the run. Only
   this process, by `(pid, start time)`, can end the run: its id alone
   isn't enough. Once the broker has the config, `deadbolt run` drops the
   secrets only routes use, so it keeps (and masks in the command's
   output) only the ones the command's variables hold. The command
   inherits the zero core-dump limit.
2. It starts `deadbolt broker --fd 0` with an empty environment, in its own
   process group, and writes a JSON config with the secrets and its own
   `(pid, start time)` to the broker's stdin.
3. The broker hardens itself first: `RLIMIT_CORE` 0, `PR_SET_DUMPABLE` 0
   on Linux, and `PT_DENY_ATTACH` in release builds on macOS. It reads the
   config, points stdin at `/dev/null`, binds `127.0.0.1:0` and prints
   `{"port":N}`.
4. On each `accept()`, the broker looks for the client's socket among the
   run's process and its descendants (`deadbolt_os::net`). On macOS it
   uses `proc_listchildpids` and `PROC_PIDFDSOCKETINFO`. On Linux it reads
   `/proc/net/tcp` and `/proc/<pid>/fd`. A connection from any other
   process gets `403` before its request is read, and the connection
   closes after that one answer. The owner found is then named by `(pid,
   start time)`, its ancestry is walked back to the run by start time,
   and it must still hold the socket afterwards, so a pid that exits and
   is reused mid-check isn't let in. Any connection must send a request's
   head within 10 s. This also covers a
   process of the same user that read the placeholder from `ps eww`. The
   lookup checks a few pids rather than every process on the system. On a
   Mac it takes about 10–30 µs. On Linux it is one exact `NETLINK_SOCK_DIAG`
   query. A kernel without `CONFIG_INET_DIAG` falls back to
   `/proc/net/tcp`, which costs about 8 ms per connection on a 32 GB VM
   because the kernel walks its whole connection hash table to print it.
5. Each request is checked before its body is read:
   - The request target must be in origin form.
   - The path must be canonical. The broker refuses `//`, `.` or `..`
     segments, `%2e`, `%2f`, `%5c`, `%3b`, `%00`, control characters,
     backslashes and `;` parameters.
   - The query must be clean.
   - The route must allow the method and the path.
   - A route with `prefix=` or `glob=` refuses `x-amz-copy-source` and
     `x-amz-rename-source` outright: they name a second object (another
     bucket's, a version) that the path scope can't see. Copy and rename
     need a route with no path scope.
   - `Authorization`, `Host`, `Content-Length`, `Transfer-Encoding` and
     the signing headers may appear at most once each.
   - The caller must present the route's placeholder. The broker compares it
     in constant time.

   The broker drops hop-by-hop headers and re-frames the body itself.
6. Bearer routes replace the header with the token. SigV4 routes check
   `Credential=<placeholder>/...` and drop the caller's signature, date,
   token and host. They then sign the request again with the real key for
   the route's region and service, over the SHA-256 of the buffered body.
   `aws-chunked` bodies (`STREAMING-...`) are decoded first, and their
   `x-amz-checksum-*` trailers become signed headers. The body must end
   with an empty line and nothing after it, and an
   `x-amz-decoded-content-length` that isn't a number is `400`. Presigned
   URLs are refused: any query parameter named `X-Amz-*` once
   percent-decoded.
7. Redirects are never followed: any 3xx except 304 becomes `502`, without
   its `Location`. The upstream is always asked for `Accept-Encoding:
   identity`, and a compressed answer is `502`. A real secret reflected in
   a response header or body comes back as `*`s of the same length, so
   `Content-Length` stays correct. That covers the secret, its URL
   encoding in either case of hex, and its base64 in the standard and
   URL-safe alphabets, also inside a longer encoded value (`base64("Bearer
   " + token)`). There, the one or two characters it shares with its
   neighbours stay.
8. The broker exits when the command ends (`deadbolt run` stops it) or
   when the run's process is gone (it checks every 250 ms).

## Limits

- A path scope can't constrain a GraphQL or RPC endpoint.
- A process in the run's tree can hand its socket to an outsider, but it
  could hand over the placeholder just as easily.
- A descendant that double-forks and reparents to launchd or init leaves
  the tree, so its connections are refused.
- On Linux, a process that made itself undumpable hides its fds. The
  broker can't find it, so it refuses that process's connections.
- `gh` insists on HTTPS for a custom host. Use `curl` against the route or
  `deadbolt run --env` for it.
- No activity record is written per brokered request yet.
