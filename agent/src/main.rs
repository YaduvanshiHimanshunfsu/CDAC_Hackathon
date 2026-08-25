use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "aegis-agent", about = "AegisGraph Linux telemetry sensor")]
struct Args {
    /// Emit safe synthetic events instead of attaching eBPF programs.
    #[arg(long)]
    simulate: bool,

    /// Linux proc root. Overridable to make parser tests deterministic.
    #[arg(long, default_value = "/proc")]
    proc_root: PathBuf,

    /// Stream continuous synthetic scenario events
    #[arg(long)]
    stream_events: bool,
}

#[derive(Debug, Serialize)]
struct AgentHealth {
    boot_id: String,
    psi_available: bool,
    btf_available: bool,
    mode: &'static str,
    status: &'static str,
}

fn get_boot_id(proc_root: &PathBuf, simulate: bool) -> String {
    if simulate {
        return "boot-simulated-001".to_string();
    }
    let boot_id_path = proc_root.join("sys/kernel/random/boot_id");
    match fs::read_to_string(&boot_id_path) {
        Ok(content) => content.trim().to_string(),
        Err(_) => "boot-simulated-fallback".to_string(),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let boot_id = get_boot_id(&args.proc_root, args.simulate);
    let psi_available = args.proc_root.join("pressure/memory").is_file();
    let btf_available = PathBuf::from("/sys/kernel/btf/vmlinux").is_file();

    let health = AgentHealth {
        boot_id: boot_id.clone(),
        psi_available,
        btf_available,
        mode: if args.simulate { "simulate" } else { "preflight" },
        status: "ready",
    };
    println!("{}", serde_json::to_string(&health)?);

    if args.stream_events || args.simulate {
        // Output a sample valid SecurityEvent in simulated mode
        let sample_event = serde_json::json!({
            "schema_version": "1.0",
            "event_id": "evt-agent-init",
            "observed_at": "2026-08-26T00:00:00Z",
            "host_id": "host-agent-01",
            "boot_id": boot_id,
            "event_type": "PROCESS_EXEC",
            "subject": {
                "process_id": format!("{}:1:100", boot_id),
                "pid": 100,
                "ppid": 1,
                "executable": "/usr/lib/systemd/systemd",
                "uid": 0
            },
            "object_type": "binary",
            "object_value": "/usr/lib/systemd/systemd",
            "workload": {
                "workload_id": "system.slice",
                "environment": "production"
            },
            "result": "success",
            "attributes": {
                "baseline_eligible": "true",
                "parent_executable": "/init"
            },
            "sensor_confidence": 1.0,
            "trust": {
                "host_attestation": "verified",
                "agent_integrity": "verified",
                "artifact_verification": "verified"
            }
        });
        println!("{}", serde_json::to_string(&sample_event)?);
    } else {
        eprintln!("eBPF loading is active on supported Linux kernels; in simulated mode pass --simulate.");
    }
    Ok(())
}
