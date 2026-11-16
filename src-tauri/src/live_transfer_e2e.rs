//! Live checks for the sudo upload fallback and cross-connection copy
//! against a real server. Ignored by default; run with
//! `RSHELL_LIVE_CONNS=<json> [RSHELL_LIVE_MASTER_KEY=<dev-master-key.dat>]
//! cargo test --lib live_transfer -- --ignored --nocapture`.
//! The JSON maps a connection name to host/port/username/privateKeyPath and
//! the still-sealed passphrase/totpSecret. Everything it creates on the
//! server is named `rshell-live-*` and removed at the end.

use std::sync::Arc;

use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::ssh::{AuthMethod, Client, SshClient, SshConfig};
use crate::sudo_upload::{exec, quote};

type Session = Arc<russh::client::Handle<Client>>;

fn config(name: &str) -> SshConfig {
    let conns: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("RSHELL_LIVE_CONNS").unwrap()).unwrap(),
    )
    .unwrap();
    let c = &conns[name];
    // A dev build's key file, or the installed app's OS-keychain key.
    let key_file = std::env::var("RSHELL_LIVE_MASTER_KEY").ok().map(std::path::PathBuf::from);
    let key = crate::commands::master_key(key_file.as_deref()).unwrap();
    let open = |field: &str| -> Option<String> {
        let sealed = c[field].as_str().unwrap_or("");
        (!sealed.is_empty()).then(|| {
            crate::commands::open_with_key(&key, sealed, b"")
                .unwrap_or_else(|e| panic!("cannot open {field}: {e}"))
        })
    };
    SshConfig {
        host: c["host"].as_str().unwrap().into(),
        port: c["port"].as_u64().unwrap() as u16,
        username: c["username"].as_str().unwrap().into(),
        auth_method: AuthMethod::PublicKey {
            key_path: c["privateKeyPath"].as_str().unwrap().into(),
            passphrase: open("passphrase"),
        },
        totp_secret: open("totpSecret"),
        compression: false,
        keepalive_interval: None,
        keepalive_max: None,
        proxy: None,
        tunnel: None,
        host_key_policy: Default::default(),
        connect_timeout: 15,
        x11: None,
    }
}

async fn connect(name: &str) -> (SshClient, Session) {
    let mut client = SshClient::new();
    client.connect(&config(name)).await.expect("connect");
    let session = client.transfer_session().unwrap();
    (client, session)
}

async fn sh(session: &Session, command: &str) -> String {
    let (code, out) = exec(session, command).await.unwrap();
    assert_eq!(code, 0, "`{}` failed: {}", command, out);
    out.trim().to_string()
}

fn local_file(content: &str) -> tempfile::TempPath {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), content).unwrap();
    file.into_temp_path()
}

async fn scenarios(a: &Session, b: &Session, tag: &str) {
    let cancel = CancellationToken::new();
    let etc = format!("/etc/rshell-live-{tag}");
    let tmp = format!("/tmp/rshell-live-{tag}");

    // 1. New file in a root-owned directory: plain SFTP is denied, so the
    //    sudo fallback installs it as root with 0644.
    let src = local_file("new-cert\n");
    let dest = format!("{etc}-new.crt");
    let n = crate::sudo_upload::upload_file(
        std::slice::from_ref(a), src.to_str().unwrap(), &dest, None, &cancel,
    )
    .await
    .expect("sudo upload of a new file");
    assert_eq!(n, 9);
    assert_eq!(sh(a, &format!("sudo -n stat -c '%U %a' {}", quote(&dest))).await, "root 644");
    assert_eq!(sh(a, &format!("sudo -n cat {}", quote(&dest))).await, "new-cert");
    println!("ok 1: new file in /etc installed via sudo (root 644)");

    // 2. Replacing an existing root 0600 file keeps owner and mode.
    let dest = format!("{etc}-existing.key");
    sh(a, &format!("echo old | sudo -n tee {d} >/dev/null && sudo -n chmod 600 {d}", d = quote(&dest))).await;
    let src = local_file("replaced\n");
    crate::sudo_upload::upload_file(std::slice::from_ref(a), src.to_str().unwrap(), &dest, None, &cancel)
        .await
        .expect("sudo upload over an existing file");
    assert_eq!(sh(a, &format!("sudo -n stat -c '%U %a' {}", quote(&dest))).await, "root 600");
    assert_eq!(sh(a, &format!("sudo -n cat {}", quote(&dest))).await, "replaced");
    println!("ok 2: overwrite kept root 600");

    // 3. A writable target takes the plain SFTP path (owned by the user).
    let dest = format!("{tmp}-plain.txt");
    let src = local_file("plain\n");
    crate::sudo_upload::upload_file(std::slice::from_ref(a), src.to_str().unwrap(), &dest, None, &cancel)
        .await
        .unwrap();
    assert_eq!(sh(a, &format!("stat -c '%U' {}", quote(&dest))).await, "ubuntu");
    assert_eq!(sh(a, "ls /tmp/.rshell-upload.* 2>/dev/null | wc -l").await, "0");
    println!("ok 3: writable target uploaded without sudo; no temp files left");

    // 4. Cross-session file copy A → B into a root-owned directory.
    let src_path = format!("{tmp}-src.txt");
    sh(a, &format!("printf 'cross\\n' > {}", quote(&src_path))).await;
    let dest = format!("{etc}-cross.crt");
    crate::cross_copy::copy(a, &src_path, false, b, &dest, &cancel)
        .await
        .expect("cross-session file copy");
    assert_eq!(sh(b, &format!("sudo -n cat {}", quote(&dest))).await, "cross");
    println!("ok 4: cross-session file copy into /etc");

    // 5. Cross-session directory copy, to a writable and a root-owned parent.
    let dir = format!("{tmp}-dir");
    sh(a, &format!(
        "mkdir -p {d}/sub && printf 'one\\n' > {d}/a.txt && printf '#!/bin/sh\\n' > {d}/sub/run.sh && chmod 755 {d}/sub/run.sh",
        d = quote(&dir)
    ))
    .await;
    let copy = format!("{tmp}-dir-copy");
    crate::cross_copy::copy(a, &dir, true, b, &copy, &cancel)
        .await
        .expect("cross-session dir copy to /tmp");
    assert_eq!(sh(b, &format!("cat {}/a.txt", quote(&copy))).await, "one");
    assert_eq!(sh(b, &format!("stat -c '%a' {}/sub/run.sh", quote(&copy))).await, "755");
    let etc_copy = format!("{etc}-dir-copy");
    crate::cross_copy::copy(a, &dir, true, b, &etc_copy, &cancel)
        .await
        .expect("cross-session dir copy to /etc");
    assert_eq!(sh(b, &format!("sudo -n cat {}/a.txt", quote(&etc_copy))).await, "one");
    println!("ok 5: cross-session directory copy to /tmp and /etc (modes kept)");

    // 6. An existing destination directory is refused, not merged.
    let err = crate::cross_copy::copy(a, &dir, true, b, &copy, &cancel)
        .await
        .expect_err("existing destination must be refused");
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(sh(b, &format!("ls {}", quote(&copy))).await.lines().count(), 2);
    println!("ok 6: existing destination refused: {err}");

    assert_eq!(sh(b, "ls -d /tmp/.rshell-copy.* 2>/dev/null | wc -l").await, "0");
    println!("ok: no staging files left on the server");
}

#[tokio::test]
#[ignore]
async fn live_transfer_against_real_server() {
    let name = std::env::var("RSHELL_LIVE_NAME").unwrap_or_else(|_| "Dashboard - Staging".into());
    let (mut client_a, a) = connect(&name).await;
    // Second, independent session (claims its own authenticator step).
    let (mut client_b, b) = connect(&name).await;
    println!("connected twice to {name}");

    let tag = format!("{:08x}", std::process::id());
    let result = tokio::spawn({
        let (a, b, tag) = (a.clone(), b.clone(), tag.clone());
        async move { scenarios(&a, &b, &tag).await }
    })
    .await;

    let cleanup = format!("sudo -n rm -rf /etc/rshell-live-{tag}* /tmp/rshell-live-{tag}*");
    let _ = exec(&a, &cleanup).await;
    let left = exec(&a, &format!("ls -d /etc/rshell-live-{tag}* /tmp/rshell-live-{tag}* 2>/dev/null | wc -l")).await;
    println!("cleanup: leftover entries = {:?}", left.map(|(_, o)| o.trim().to_string()));
    let _ = client_a.disconnect().await;
    let _ = client_b.disconnect().await;
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}
