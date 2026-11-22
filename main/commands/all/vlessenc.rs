use super::curve25519::gen_curve25519;
use super::mlkem768::gen_mlkem768;
use crate::main::commands::base::command::Command;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn generate_dot_config(fields: &[&str]) -> String { fields.join(".") }

pub fn cmd_vlessenc() -> Command {
    Command::new("vlessenc", "xray vlessenc", "Generate decryption/encryption json pair (VLESS Encryption)").with_run(|_| {
        let dot = |t, k: &str| generate_dot_config(&["mlkem768x25519plus", "native", t, k]);
        let (priv_k, pass, _) = gen_curve25519(None)?;
        let (seed, cli, _) = gen_mlkem768(None);
        let (sk, ck, sk_pq, ck_pq) = (
            URL_SAFE_NO_PAD.encode(priv_k), URL_SAFE_NO_PAD.encode(pass),
            URL_SAFE_NO_PAD.encode(seed), URL_SAFE_NO_PAD.encode(&cli),
        );
        Ok(format!(
            "Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.\n\n\
            Authentication: X25519, not Post-Quantum\n\"decryption\": \"{}\"\n\"encryption\": \"{}\"\n\n\
            Authentication: ML-KEM-768, Post-Quantum\n\"decryption\": \"{}\"\n\"encryption\": \"{}\"",
            dot("600s", &sk), dot("0rtt", &ck), dot("600s", &sk_pq), dot("0rtt", &ck_pq)
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vlessenc_command() {
        let cmd = cmd_vlessenc();
        let out = cmd.execute(&[]).unwrap();
        assert!(out.contains("Authentication: X25519"));
        assert!(out.contains("Authentication: ML-KEM-768"));
        assert!(out.contains("mlkem768x25519plus.native"));
    }
}
