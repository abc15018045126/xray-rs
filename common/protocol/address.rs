use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::errors::{Error, Result};
use crate::common::net::Address;

pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN: u8 = 0x02;
pub const ADDR_TYPE_IPV6: u8 = 0x03;

pub struct AddressParser {
    pub port_first: bool,
}

impl AddressParser {
    pub fn new(port_first: bool) -> Self {
        Self { port_first }
    }

    pub async fn read_address_port<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<(Address, u16)> {
        if self.port_first {
            let port = reader.read_u16().await.map_err(Error::Io)?;
            let addr = self.read_address(reader).await?;
            Ok((addr, port))
        } else {
            let addr = self.read_address(reader).await?;
            let port = reader.read_u16().await.map_err(Error::Io)?;
            Ok((addr, port))
        }
    }

    pub async fn write_address_port<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        addr: &Address,
        port: u16,
    ) -> Result<()> {
        if self.port_first {
            writer.write_u16(port).await.map_err(Error::Io)?;
            self.write_address(writer, addr).await?;
        } else {
            self.write_address(writer, addr).await?;
            writer.write_u16(port).await.map_err(Error::Io)?;
        }
        Ok(())
    }

    pub async fn read_address<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Address> {
        match reader.read_u8().await.map_err(Error::Io)? {
            ADDR_TYPE_IPV4 => { let mut b = [0u8; 4]; reader.read_exact(&mut b).await.map_err(Error::Io)?; Ok(Address::Ipv4(Ipv4Addr::from(b))) }
            ADDR_TYPE_IPV6 => { let mut b = [0u8; 16]; reader.read_exact(&mut b).await.map_err(Error::Io)?; Ok(Address::Ipv6(Ipv6Addr::from(b))) }
            ADDR_TYPE_DOMAIN => {
                let mut b = vec![0u8; reader.read_u8().await.map_err(Error::Io)? as usize];
                reader.read_exact(&mut b).await.map_err(Error::Io)?;
                Address::from_str(&String::from_utf8(b).map_err(|_| Error::Protocol("invalid utf8 domain".into()))?)
            }
            other => Err(Error::Protocol(format!("unknown address type: {}", other))),
        }
    }

    pub async fn write_address<W: AsyncWrite + Unpin>(&self, writer: &mut W, addr: &Address) -> Result<()> {
        match addr {
            Address::Ipv4(ip) => {
                writer.write_u8(ADDR_TYPE_IPV4).await.map_err(Error::Io)?;
                writer.write_all(&ip.octets()).await.map_err(Error::Io)?;
            }
            Address::Ipv6(ip) => {
                writer.write_u8(ADDR_TYPE_IPV6).await.map_err(Error::Io)?;
                writer.write_all(&ip.octets()).await.map_err(Error::Io)?;
            }
            Address::Domain(d) => {
                writer.write_all(&[ADDR_TYPE_DOMAIN, d.len() as u8]).await.map_err(Error::Io)?;
                writer.write_all(d.as_bytes()).await.map_err(Error::Io)?;
            }
        }
        Ok(())
    }
}
