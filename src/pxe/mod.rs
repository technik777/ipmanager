use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use std::str::FromStr;

use crate::config::Config;
use crate::domain::mac::MacAddr;

#[derive(Debug, Clone)]
pub struct HostPxe {
    pub mac_address: String,
    pub os_type: Option<String>,
}

pub async fn write_ipxe_configs(hosts: &[HostPxe], config: &Config) -> Result<()> {
    let configs_dir = std::path::Path::new(&config.tftp_root_dir).join("pxe-configs");
    tokio::fs::create_dir_all(&configs_dir)
        .await
        .context("failed to create pxe-configs directory")?;

    let assets_rel = assets_relative_path(config);
    let tftp_base = format!("tftp://{}/{}", config.pxe_tftp_server, assets_rel);

    for host in hosts {
        let mac = MacAddr::from_str(host.mac_address.trim()).with_context(|| {
            format!("invalid mac_address in hosts table: {}", host.mac_address)
        })?;
        let script = render_ipxe_script(host.os_type.as_deref(), &tftp_base);
        let file_path = configs_dir.join(format!("{}.ipxe", mac));
        let mut file = tokio::fs::File::create(&file_path)
            .await
            .with_context(|| format!("failed to create ipxe config {}", file_path.display()))?;
        file.write_all(script.as_bytes()).await?;
        file.flush().await?;
    }

    Ok(())
}

fn assets_relative_path(config: &Config) -> String {
    let tftp_root = std::path::Path::new(&config.tftp_root_dir);
    let assets_dir = std::path::Path::new(&config.pxe_assets_dir);
    let rel = assets_dir
        .strip_prefix(tftp_root)
        .ok()
        .and_then(|path| path.to_str())
        .map(|v| v.trim_start_matches('/').to_string());
    rel.filter(|v| !v.is_empty())
        .unwrap_or_else(|| "pxe-assets".to_string())
}

fn render_ipxe_script(os_type: Option<&str>, tftp_base: &str) -> String {
    match os_type.map(|v| v.trim().to_lowercase()) {
        Some(ref v) if v == "ubuntu" => format!(
            "#!ipxe\nkernel {}/ubuntu/vmlinuz initrd=initrd.img\ninitrd {}/ubuntu/initrd.img\nboot\n",
            tftp_base, tftp_base
        ),
        Some(ref v) if v == "custom" => standard_menu(tftp_base),
        _ => standard_menu(tftp_base),
    }
}

fn standard_menu(tftp_base: &str) -> String {
    format!(
        "#!ipxe\n\
menu IPManager Boot\n\
item --key u ubuntu Ubuntu\n\
item --key c custom Custom\n\
choose --default custom --timeout 5000 target || exit\n\
goto ${{target}}\n\
:ubuntu\n\
kernel {}/ubuntu/vmlinuz initrd=initrd.img\n\
initrd {}/ubuntu/initrd.img\n\
boot\n\
:custom\n\
chain {}/custom.ipxe || shell\n",
        tftp_base, tftp_base, tftp_base
    )
}
