use std::io::Write;
use std::process::{Command, Stdio};

pub fn run_iptables_restore(rules: &str) -> Result<(), std::io::Error> {
    let mut proc = Command::new("iptables-restore")
        .arg("--wait")
        .arg("--noflush")
        .stdin(Stdio::piped())
        .spawn()?;
    proc.stdin.take().unwrap().write_all(rules.as_bytes())?;
    proc.wait()?;

    Ok(())
}

enum ConfigType {
    ConfigByUser,
}

pub struct ConfiguredIptables {
    conf_type: ConfigType,
}

impl Drop for ConfiguredIptables {
    fn drop(&mut self) {
        let _ = match self.conf_type {
            ConfigType::ConfigByUser => unload_config_by_user(),
        };
    }
}

pub fn config_by_user(
    queue_id: u16,
    queue_bypass: bool,
    uname: &str,
    bitcoin_port: u32,
) -> Result<ConfiguredIptables, Box<dyn std::error::Error>> {
    let queue_bypass_flag = if queue_bypass { "--queue-bypass" } else { "" };
    let queue_args = format!("--queue-num {} {}\n", queue_id, queue_bypass_flag);

    let rules = format!(
        "\
*mangle
:BIP324_DECR_QUEUE_IN - [0:0]
:BIP324_DECR_QUEUE_OUT - [0:0]

-A INPUT -j BIP324_DECR_QUEUE_IN
-A OUTPUT -j BIP324_DECR_QUEUE_OUT

# Skip system ports for safety
-A BIP324_DECR_QUEUE_IN -p tcp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_IN -p tcp -m multiport --sports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_IN -p udp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_IN -p udp -m multiport --sports 0:1023 -j RETURN

-A BIP324_DECR_QUEUE_IN -m connmark --mark 0x1 -j NFQUEUE {queue_args}
# Generic way of ensuring that a packet matched by any of the NFQEUEUE rules is connmarked
-A BIP324_DECR_QUEUE_IN -j CONNMARK --set-xmark 0x1/0x1
-A BIP324_DECR_QUEUE_IN -p tcp -m tcp --dport {bitcoin_port} -j NFQUEUE {queue_args}
-A BIP324_DECR_QUEUE_IN -j CONNMARK --set-xmark 0x0/0x1

# Skip system ports for safety
-A BIP324_DECR_QUEUE_OUT -p tcp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_OUT -p tcp -m multiport --sports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_OUT -p udp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_OUT -p udp -m multiport --sports 0:1023 -j RETURN

# Skip bitcoin mainnet rpc
-A BIP324_DECR_QUEUE_OUT -p tcp -m tcp --dport 8332 -m owner --uid-owner {uname} -j RETURN
-A BIP324_DECR_QUEUE_OUT -p tcp -m tcp --sport 8332 -m owner --uid-owner {uname} -j RETURN
-A BIP324_DECR_QUEUE_OUT -m connmark --mark 0x1 -j NFQUEUE {queue_args}
# Generic way of ensuring that a packet matched by any of the NFQEUEUE rules is connmarked
-A BIP324_DECR_QUEUE_OUT -j CONNMARK --set-xmark 0x1/0x1
-A BIP324_DECR_QUEUE_OUT -m owner --uid-owner {uname} -j NFQUEUE {queue_args}
-A BIP324_DECR_QUEUE_OUT -j CONNMARK --set-xmark 0x0/0x1

COMMIT
"
    );

    run_iptables_restore(&rules)?;

    Ok(ConfiguredIptables {
        conf_type: ConfigType::ConfigByUser,
    })
}

fn unload_config_by_user() -> Result<(), Box<dyn std::error::Error>> {
    let rules = format!(
        "\
*mangle
-F BIP324_DECR_QUEUE_IN
-D INPUT -j BIP324_DECR_QUEUE_IN
-X BIP324_DECR_QUEUE_IN

-F BIP324_DECR_QUEUE_OUT
-D OUTPUT -j BIP324_DECR_QUEUE_OUT
-X BIP324_DECR_QUEUE_OUT

COMMIT
"
    );

    run_iptables_restore(&rules)?;

    Ok(())
}
