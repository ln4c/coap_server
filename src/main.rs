use std::{
    fs,
    io::BufRead,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use libcoap_rs::{
    message::{CoapMessageCommon, CoapRequest, CoapResponse},
    protocol::{CoapRequestCode, CoapResponseCode},
    session::{CoapServerSession, CoapSessionCommon},
    CoapContext, CoapRequestHandler, CoapResource, OscoreConf,
};

fn main() {
    // This will give us a SocketAddress with a port in the local port range automatically
    // assigned by the operating system.
    // Because the UdpSocket goes out of scope, the Port will be free for usage by libcoap.
    // This seems to be the only portable way to get a port number assigned from the operating
    // system.
    // It is assumed here that after unbinding the temporary socket, the OS will not reassign
    // this port until we bind it again. This should work in most cases (unless we run on a
    // system with very few free ports), because at least Linux will not reuse port numbers
    // unless necessary, see https://unix.stackexchange.com/a/132524.
    let server_address = UdpSocket::bind("localhost:5683")
        .expect("Failed to bind server socket")
        .local_addr()
        .expect("Failed to get server socket address");

    // a new CoAP context and bind to the generated SocketAddr.
    let mut context = CoapContext::new().expect("Failed to create CoAP context");
    context
        .add_endpoint_udp(server_address)
        .expect("Unable to add/bind to endpoint");

    // read bytes from oscore_conf
    let bytes = fs::read("oscore_conf").expect("Could not read oscore_conf file");

    // edhoc example
    let bytes = edhoc(bytes, "1234", "4321", "edhoc");

    // create the oscore_conf using std
    let oscore_conf = OscoreConf::new_std(1, &bytes).expect("Could not create oscore_conf");

    // add oscore_conf to context
    context
        .oscore_server(oscore_conf)
        .expect("Adding the oscore_conf failed");

    // add new recipient to context
    context
        .new_oscore_recipient("client")
        .expect("Adding the 'client' failed");

    // Create a new resource that is available at the URI path `hello_world`
    // The second argument can be used to provide any kind of user-specific data, which will
    // then be passed to the handler function.
    let resource = CoapResource::new("hello_world", (), false);
    // Set a method handler for the GET method.
    resource.set_method_handler(
        CoapRequestCode::Get,
        Some(CoapRequestHandler::new(
            // The handler can be a lambda or some other kind of function.
            // Using methods is also possible by setting the resource's user data to an instance
            // of the struct, as the first argument will then be a mutable reference to the
            // user data. Methods will then use this user data as the `&mut self` reference.
            //
            // The provided CoapResponse is already filled with the correct token to be
            // interpreted as a response to the correct request by the client.
            |completed: &mut (),
             session: &mut CoapServerSession,
             request: &CoapRequest,
             mut response: CoapResponse| {
                // Set content of the response message to "Hello World!"
                let data = Vec::<u8>::from("Hello World!".as_bytes());
                response.set_data(Some(data));
                // Set the response code to 2.00 "Content"
                response.set_code(CoapResponseCode::Content);
                // Send the response message.
                session.send(response).expect("Unable to send response");
                #[cfg(debug_assertions)]
                println!("DEBUG: Replied to a request on hello_world");
            },
        )),
    );

    // Add the resource to the context.
    context.add_resource(resource);
    loop {
        // process IO in a loop...
        if let Err(e) = context.do_io(Some(Duration::from_secs(1))) {
            break;
        }
        // ...until we want to shut down.
    }
    // Properly shut down, completing outstanding IO requests and properly closing sessions.
    context.shutdown(Some(Duration::from_secs(0))).unwrap();
}

fn edhoc(bytes: Vec<u8>, secret: &str, salt: &str, recipient_id: &str) -> Vec<u8> {
    let mut lines: Vec<String> = core::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| line.to_string())
        .collect();
    let mut recipient_found = false;
    for line in lines.iter_mut() {
        if line.starts_with("master_secret") {
            *line = format!("master_secret,hex,\"{}\"", secret);
        } else if line.starts_with("master_salt") {
            *line = format!("master_salt,hex,\"{}\"", salt);
        } else if line.starts_with("recipient_id") {
            *line = format!("recipient_id,ascii,\"{}\"", recipient_id);
            recipient_found = true;
        }
    }
    if !recipient_found {
        for i in 0..lines.len() {
            if lines[i].starts_with("sender_id") {
                lines.insert(i + 1, format!("recipient_id,ascii,\"{}\"", recipient_id));
            }
        }
    }
    let lines = lines.join("\n");
    println!("{}", lines);
    lines.into_bytes()
}
