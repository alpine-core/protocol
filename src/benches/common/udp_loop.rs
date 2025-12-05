use std::io;
use std::net::UdpSocket;

pub fn bind_socket() -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(("127.0.0.1", 0))?;
    socket.set_nonblocking(false)?;
    Ok(socket)
}
