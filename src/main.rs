use anyhow::Result;
use clap::Parser;
use postgres::{fallible_iterator::FallibleIterator, Client, NoTls, Notification};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

shadow_rs::shadow!(build);

/// IP Ban management daemon
#[derive(Parser, Debug)]
#[command(author, version=build::CLAP_LONG_VERSION, about, long_about = None)]
pub struct Args {
    /// Where should we find our list of banned IPs
    #[arg(short = 'd', long, default_value = "user=test host=localhost")]
    pub dsn: String,
}

fn main() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();

    let args = Args::parse();
    log::info!(
        "shm-ipband {} built on {}",
        build::SHORT_COMMIT,
        build::BUILD_TIME
    );

    let mut db = Client::connect(args.dsn.as_str(), NoTls)?;

    db.batch_execute("SET application_name TO 'shm-ipband'")?;
    update_bans(&mut db)?;

    db.batch_execute("LISTEN bans")?;

    loop {
        let notifications: Vec<Notification> = db.notifications().blocking_iter().collect()?;
        for notification in notifications {
            if notification.channel() == "bans" {
                update_bans(&mut db)?;
            }
        }
    }
}

fn update_bans(db: &mut Client) -> Result<()> {
    let rows = db.query(
        "SELECT ip FROM bans WHERE mode = 'firewall' AND added < now() AND (expires > now() OR expires IS NULL)",
        &[],
    )?;
    let n = rows.len();
    log::info!("Setting {} bans", n);

    // hash:net for giving a different CIDR to each entry
    let mut ipset_cmds = Vec::with_capacity(n + 10);
    ipset_cmds.push(format!("create ipband hash:ip hashsize {} -exist", n));
    ipset_cmds.push(format!("create ipband_new hash:ip hashsize {} -exist", n));
    for row in rows {
        // FIXME: range bans are silently converted to single-IP bans
        // (python version silently dropped range bans, so this is less-bad...)
        let ip: IpAddr = row.get(0);
        ipset_cmds.push(format!("add ipband_new {}", ip));
    }
    ipset_cmds.push("swap ipband ipband_new".to_string());
    ipset_cmds.push("flush ipband_new".to_string());

    let mut ipset = Command::new("ipset")
        .arg("restore")
        .stdin(Stdio::piped())
        .spawn()?;
    writeln!(
        ipset
            .stdin
            .as_ref()
            .ok_or(anyhow::anyhow!("Failed to write to ipset"))?,
        "{}",
        ipset_cmds.join("\n")
    )?;
    ipset.wait()?;

    let iptables = "iptables -L -n | grep ipband | grep 443 || iptables -A INPUT -m set --match-set ipband src -p tcp -m multiport --dports 80,443 -j DROP";
    Command::new("/bin/sh").args(["-c", iptables]).output()?;

    Ok(())
}
