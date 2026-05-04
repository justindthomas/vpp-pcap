// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Justin Thomas

//! `vpp-pcap` — tcpdump-style live capture for FD.io VPP.
//!
//! Talks to the `pcap_stream` plugin's text control socket. See
//! ../../DESIGN.md and ../../plugin/pcap_stream_drain.c for the
//! wire-protocol definition.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};

const DEFAULT_SOCK: &str = "/run/vpp/pcap-stream.sock";

#[derive(Parser, Debug)]
#[command(name = "vpp-pcap", version, about = "tcpdump-style live capture for FD.io VPP", long_about = None)]
struct Cli {
    /// Path to the pcap_stream plugin's control socket.
    #[arg(long, default_value = DEFAULT_SOCK, global = true)]
    server: PathBuf,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Capture options when no subcommand is given (the default
    /// `vpp-pcap [opts] '<bpf>'` form).
    #[command(flatten)]
    capture: CaptureOpts,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List active sessions on the server.
    List,
    /// Tear down a session by id.
    Kill {
        id: u32,
    },
    /// Print stats for a session by id.
    Stats {
        id: u32,
    },
    /// Send a hex-encoded packet through every active session
    /// (test path; bypasses the dataplane). Useful while the
    /// feature-arc node is still under construction.
    Inject {
        /// Hex-encoded ethernet-framed packet bytes.
        hex: String,
    },
}

#[derive(Args, Debug, Default)]
struct CaptureOpts {
    /// Interface name (or "any"). Required for capture mode.
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// Direction: rx, tx, drop, or any.
    #[arg(short = 'd', long, default_value = "any")]
    direction: String,

    /// Bytes per packet to capture (0 = full).
    #[arg(short = 's', long, default_value_t = 262144)]
    snaplen: u32,

    /// Stop after N packets (0 = unlimited).
    #[arg(short = 'c', long, default_value_t = 0)]
    count: u64,

    /// Write captured packets to a pcap file (- = stdout).
    #[arg(short = 'w', long)]
    write: Option<PathBuf>,

    /// Pipe through `tcpdump -nn -r -` for human-readable decoding.
    #[arg(long)]
    print: bool,

    /// libpcap-syntax filter expression.
    filter: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::List) => cmd_list(&cli.server),
        Some(Cmd::Kill { id }) => cmd_kill(&cli.server, id),
        Some(Cmd::Stats { id }) => cmd_stats(&cli.server, id),
        Some(Cmd::Inject { hex }) => cmd_inject(&cli.server, &hex),
        None => cmd_capture(&cli.server, cli.capture),
    }
}

// ----- Control protocol helpers -----

fn connect(sock: &PathBuf) -> Result<UnixStream> {
    UnixStream::connect(sock)
        .with_context(|| format!("connect to control socket at {}", sock.display()))
}

/// Read one line (terminated by '\n') from the stream. Returns the
/// line without the trailing newline.
fn read_line(s: &mut UnixStream) -> Result<String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte)?;
        if n == 0 {
            bail!("control socket closed mid-response");
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8(buf).context("non-utf8 in control response")?)
}

fn send_line(s: &mut UnixStream, line: &str) -> Result<()> {
    s.write_all(line.as_bytes())?;
    s.write_all(b"\n")?;
    s.flush()?;
    Ok(())
}

/// Parse `key=value` pairs out of an `ok ...` or `session ...` line.
/// Quoted values (single or double quotes) are unwrapped. Returns
/// pairs in declaration order.
fn parse_kv(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        let kstart = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b' ' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            // bare token (the verb) — skip
            continue;
        }
        let key = String::from_utf8_lossy(&bytes[kstart..i]).into_owned();
        i += 1; // skip '='
        let val: String;
        if i < bytes.len() && (bytes[i] == b'\'' || bytes[i] == b'"') {
            let q = bytes[i];
            i += 1;
            let vstart = i;
            while i < bytes.len() && bytes[i] != q {
                i += 1;
            }
            val = String::from_utf8_lossy(&bytes[vstart..i]).into_owned();
            if i < bytes.len() {
                i += 1; // skip closing quote
            }
        } else {
            let vstart = i;
            while i < bytes.len() && bytes[i] != b' ' {
                i += 1;
            }
            val = String::from_utf8_lossy(&bytes[vstart..i]).into_owned();
        }
        out.push((key, val));
    }
    out
}

fn kv_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Quote a value if it contains whitespace.
fn quote_if_needed(s: &str) -> String {
    if s.chars().any(char::is_whitespace) {
        format!("'{}'", s.replace('\'', ""))
    } else {
        s.to_string()
    }
}

// ----- Commands -----

fn cmd_list(sock: &PathBuf) -> Result<()> {
    let mut s = connect(sock)?;
    send_line(&mut s, "list")?;
    let header = read_line(&mut s)?;
    if !header.starts_with("ok") {
        bail!("server: {header}");
    }
    let pairs = parse_kv(&header);
    let n: usize = kv_get(&pairs, "sessions")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    for _ in 0..n {
        let line = read_line(&mut s)?;
        println!("{line}");
    }
    Ok(())
}

fn cmd_kill(sock: &PathBuf, id: u32) -> Result<()> {
    let mut s = connect(sock)?;
    send_line(&mut s, &format!("delete id={id}"))?;
    let resp = read_line(&mut s)?;
    println!("{resp}");
    Ok(())
}

fn cmd_stats(sock: &PathBuf, id: u32) -> Result<()> {
    let mut s = connect(sock)?;
    send_line(&mut s, &format!("stats id={id}"))?;
    let resp = read_line(&mut s)?;
    println!("{resp}");
    Ok(())
}

fn cmd_inject(sock: &PathBuf, hex: &str) -> Result<()> {
    let mut s = connect(sock)?;
    send_line(&mut s, &format!("inject hex={hex}"))?;
    let resp = read_line(&mut s)?;
    println!("{resp}");
    Ok(())
}

fn cmd_capture(sock: &PathBuf, opts: CaptureOpts) -> Result<()> {
    let iface = opts.interface.as_deref().unwrap_or("any");
    let dir = opts.direction.as_str();
    let filter = opts.filter.unwrap_or_default();

    let mut s = connect(sock)?;
    let line = format!(
        "create iface={iface} dir={dir} snaplen={snap} max={max} filter={f}",
        snap = opts.snaplen,
        max = opts.count,
        f = quote_if_needed(&filter),
    );
    send_line(&mut s, &line)?;
    let resp = read_line(&mut s)?;
    if !resp.starts_with("ok") {
        bail!("server: {resp}");
    }

    // Pick the output sink.
    let (mut sink, mut child): (Box<dyn Write>, Option<std::process::Child>) =
        if opts.print {
            // pipe through tcpdump
            let mut c = Command::new("tcpdump")
                .args(["-nn", "-r", "-"])
                .stdin(Stdio::piped())
                .spawn()
                .context("spawn `tcpdump -nn -r -`")?;
            let stdin = c.stdin.take().ok_or_else(|| anyhow!("tcpdump stdin"))?;
            (Box::new(stdin), Some(c))
        } else {
            match opts.write.as_deref() {
                Some(p) if p.to_str() == Some("-") => {
                    (Box::new(io::stdout()), None)
                }
                Some(p) => {
                    let f = std::fs::File::create(p)
                        .with_context(|| format!("create {}", p.display()))?;
                    (Box::new(f), None)
                }
                None => (Box::new(io::stdout()), None),
            }
        };

    // Splice everything that arrives on the control socket (which is
    // now the pcap-data stream) to the sink. Ctrl-C or server-side
    // session destroy ends the loop.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if sink.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    if let Some(c) = child.as_mut() {
        let _ = c.wait();
    }
    Ok(())
}
