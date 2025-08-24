use std::{io, net::SocketAddr};

use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

pub async fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

pub async fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

pub async fn send_json<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let line = serde_json::to_string(msg).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    Ok(())
}

pub async fn recv_json<T: DeserializeOwned>(stream: &mut TcpStream) -> io::Result<T> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let val = serde_json::from_str::<T>(&line).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(val)
}
