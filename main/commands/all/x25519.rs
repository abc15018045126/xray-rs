use super::curve25519::gen_curve25519;
use crate::main::commands::base::command::Command;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

pub fn cmd_x25519() -> Command {
    Command::new("x25519", "xray x25519 [-i key] [--std-encoding]", "Generate key pair for X25519 key exchange (REALITY, VLESS Encryption)").with_run(|args| {
        let (mut input_key, mut std_enc, mut i) = (None, false, 0);
        while i < args.len() {
            if args[i] == "--std-encoding" { std_enc = true; }
            else if args[i] == "-i" && i + 1 < args.len() {
                let dec = if std_enc { STANDARD.decode(args[i + 1]) } else { URL_SAFE_NO_PAD.decode(args[i + 1]) };
                if let Ok(key) = dec { input_key = Some(key); }
                i += 1;
            }
            i += 1;
        }
        let (priv_k, pub_k, hash) = gen_curve25519(input_key.as_deref())?;
        let enc = |b: &[u8]| if std_enc { STANDARD.encode(b) } else { URL_SAFE_NO_PAD.encode(b) };
        Ok(format!("PrivateKey: {}\nPassword (PublicKey): {}\nHash32: {}", enc(&priv_k), enc(&pub_k), enc(&hash)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_x25519_command() {
        let cmd = cmd_x25519();
        let res = cmd.execute(&[]).unwrap();
        assert!(res.contains("PrivateKey:"));
        assert!(res.contains("Password (PublicKey):"));
        let std_res = cmd.execute(&["--std-encoding"]).unwrap();
        assert!(std_res.contains("PrivateKey:"));
    }
}
