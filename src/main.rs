use std::net::SocketAddr;
use std::net::UdpSocket;
use trust_dns_proto::{
    op::Message,
    rr::Record,
    serialize::binary::{BinEncodable, BinEncoder},
};
// rr::{DNSClass, RecordType},
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};

fn main() {
    let addr = "0.0.0.0:1053".parse::<SocketAddr>().unwrap();
    let socket = UdpSocket::bind(addr).unwrap();
    log::info!("Listening on {}", addr);

    let mut buf = vec![0u8; 512];
    loop {
        let (len, src) = socket.recv_from(&mut buf).unwrap();
        let request = buf[..len].to_vec();

        // 使用async_std的task::spawn而不是tokio的spawn
        // task::spawn(handle_request(request, src, &socket));
        handle_request(request, src, &socket);
    }
}

fn handle_request(request: Vec<u8>, src: SocketAddr, socket: &UdpSocket) {
    if let Ok(response) = parse_and_forward_request(request) {
        socket.send_to(&response, src).unwrap();
    } else {
        log::error!("Failed to parse request from {}", src);
    }
}

// 注意：首先确保已经正确处理好了`message`变量的可变权。
// 比如，如果message在之前被借用作不可变引用，确保这些借用的作用域已经结束。

fn parse_and_forward_request(request: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut message = Message::from_vec(&request)?;

    // 配置DNS解析器
    let default = Resolver::from_system_conf()?;
    let cf = Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default())?;

    let records: Vec<Record> = message
        .queries()
        .iter()
        .map(|query| -> Vec<Record> {
            let query_name = query.name().to_utf8();
            let query_name = query_name.as_str();
            let query_type = query.query_type();

            let (resolver, dns_server) = if query_name.contains(".cn.") {
                (&default, "default")
            } else {
                (&cf, "cloudflare")
            };
            log::info!(
                "query_name: {}, query_type: {}, resolver: {:?}",
                query_name,
                query_type,
                dns_server,
            );

            resolver
                .lookup(query_name, query_type)
                .unwrap()
                .record_iter()
                .map(|x| x.clone())
                .collect()
        })
        .flatten()
        .collect();
    message.add_answers(records);

    let mut buffer = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buffer);
    message.emit(&mut encoder)?;

    // 缓冲区现在包含序列化后的Message，可以发送
    Ok(buffer)
}
