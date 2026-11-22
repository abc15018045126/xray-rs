pub fn is_linux_kernel_wireguard_supported() -> bool { cfg!(target_os = "linux") }
