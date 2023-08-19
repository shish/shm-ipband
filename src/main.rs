use anyhow::Result;
use futures::channel::mpsc;
use futures::FutureExt;
use futures::{future, stream, StreamExt};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use structopt::StructOpt;
use tokio_postgres::{AsyncMessage, NoTls};

#[macro_use]
extern crate log;

#[derive(StructOpt)]
#[structopt(about = "IP Ban management daemon")]
pub struct Args {
    /// Where should we find our list of banned IPs
    #[structopt(short = "d", default_value = "user=test host=localhost")]
    pub dsn: String,

    /// This host's name
    #[structopt(short = "n")]
    pub name: Option<String>,

    /// Show version
    #[structopt(long = "version")]
    pub version: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let args = Args::from_args();
    let fqdn = gethostname::gethostname().into_string().unwrap();
    let name = match args.name {
        Some(name) => name,
        None => fqdn.split('.').next().unwrap().to_string(),
    };
    info!(
        "shm-ipband {} built on {} - running on {} ({})",
        env!("VERGEN_GIT_SHA").chars().take(7).collect::<String>(),
        env!("VERGEN_BUILD_DATE"),
        fqdn,
        name,
    );
    if args.version {
        return Ok(());
    }

    let (db, mut connection) = tokio_postgres::connect(args.dsn.as_str(), NoTls).await?;
    let (tx, mut rx) = mpsc::unbounded();
    let stream =
        stream::poll_fn(move |cx| connection.poll_message(cx).map_err(|e| panic!("{}", e)));
    let c = stream.forward(tx).map(|r| r.unwrap());
    tokio::spawn(c);

    db.query(
        format!("SET application_name TO 'shm-ipband [{}]'", name).as_str(),
        &[],
    )
    .await?;

    update_bans(&db).await?;

    db.query("LISTEN bans", &[]).await?;

    loop {
        if let Some(AsyncMessage::Notification(future_notification)) = rx.next().await {
            let notification = future::ready(Some(future_notification)).await.unwrap();
            if notification.channel() == "bans" {
                update_bans(&db).await.unwrap();
            }
        }
    }
}

async fn update_bans(db: &tokio_postgres::Client) -> Result<()> {
    let rows = db
        .query("SELECT ip FROM bans WHERE mode = 'firewall' AND added < now() AND (expires > now() OR expires IS NULL)", &[])
        .await?;
    let n = rows.len();
    info!("Setting {} bans", n);

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
    writeln!(ipset.stdin.as_ref().unwrap(), "{}", ipset_cmds.join("\n"))?;
    ipset.wait()?;

    Command::new("/bin/sh").args(["-c", "iptables -L -n | grep ipband | grep 80  || iptables -A INPUT -m set --match-set ipband src -p tcp --dport 80 -j DROP"]).output()?;
    Command::new("/bin/sh").args(["-c", "iptables -L -n | grep ipband | grep 443 || iptables -A INPUT -m set --match-set ipband src -p tcp --dport 443 -j DROP"]).output()?;

    Ok(())
}
