use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, UdpSocket},
    os::raw::c_void,
    ptr,
    time::Duration,
};

use libcoap_rs::{
    message::{response, CoapMessageCommon, CoapRequest, CoapResponse},
    protocol::{CoapRequestCode, CoapResponseCode},
    session::{CoapServerSession, CoapSessionCommon},
    CoapContext, CoapRequestHandler, CoapResource, OscoreConf,
};

// INFO: EXAMPLE IMPLEMENTATION OF save_seq_num_func
// This example uses std and fs to save the provided seq_num to a file.
// You are advised to provided your own implementation for embedded environments.
// WARNING: Writing the sequence number to flash every time may harm the lifetime of the storage!
extern "C" fn save_seq_num(seq_num: u64, _param: *mut c_void) -> i32 {
    let mut oscore_seq_safe_file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("oscore.seq")
    {
        Ok(file) => file,
        Err(_) => return 0,
    };

    // TODO: refactor this
    if let Err(_) = writeln!(oscore_seq_safe_file, "{}\n", seq_num) {
        return 0;
    }
    if let Err(_) = oscore_seq_safe_file.flush() {
        return 0;
    }

    #[cfg(debug_assertions)]
    println!("DEBUG: Saving sequence number: {}", seq_num);

    1
}

// INFO: EXAMPLE IMPLEMENTATION TO READ LAST SEQUENCE NUMBER
// This example used std and fs to retrieve the last known used sequence number from a file.
// You are advised to provide your own implementation for embedded environments.
fn read_initial_seq_num() -> Option<u64> {
    let file = match File::open("oscore.seq") {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut reader = BufReader::new(file);

    let mut line = String::new();
    if reader.read_line(&mut line).is_ok() {
        return match line.trim().parse() {
            Ok(num) => Some(num),
            Err(_) => None,
        };
    }
    None
}

// INFO: EXAMPLE TO MANIPULATE CONFIG BYTES WITH NEGOTIATED EDHOC CREDENTIALS
// This example illustrates a way to manipulate existing oscore config bytes with the updated
// credentials (secret, salt, recipient_id) using the edhoc key exchange.
// TODO: We may provide a function function to directly create oscore config bytes from this
// parameters but due to the flexibility and optinality of some keywords we have currently decided
// against it: https://libcoap.net/doc/reference/4.3.5/man_coap-oscore-conf.html
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

    #[cfg(debug_assertions)]
    println!("{}", lines);
    lines.into_bytes()
}

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

    // INFO: READ OSCORE CONFIG
    // By default we recommend reading the oscore_conf as bytes from a file using fs.
    // For embedded environments you're advised to provide your own implementation for
    // creating the oscore config bytes as std or fs may not be available.
    let bytes = fs::read("oscore_conf").expect("Could not read oscore_conf file");

    // INFO: EDHOC EXAMPLE
    // The edhoc-function currently offers an easy way to update the secret, salt and recipient_id
    // of a given config file to provide own values negotiated by EDHOC.
    let bytes = edhoc(bytes, "1234", "4321", "backend");

    // INFO: CHOOSE AN INITIAL SEQUENCE NUMBER
    // The read_initial_seq_num-function is used to try to read the last saved sequence number from
    // a file using std. It is advised to implement your own logic for retrieving this number,
    // especially for embedded environments as std or fs may not be available.
    let seq_initial = read_initial_seq_num().unwrap_or(1);

    // INFO: CREATE OSCORE CONFIG
    // Now you can use the oscore config bytes generated and the initial sequence number to create
    // an OscoreConf to use with libcoap-rs. You also have to provide a save_seq_num-function which
    // provides logic to save the current sequence number somewhere. We currently provide an
    // example implementation which saves the last sequence number to a file using fs.
    // WARNING: You are advised to provide your own implement for the save_seq_num_func as
    // especially for embedded environments std and fs may not be available. You must also consider
    // writing the sequence number to flash on every time may harm the lifetime of this storage!
    let oscore_conf =
        OscoreConf::new(seq_initial, &bytes, save_seq_num).expect("Could not create oscore_conf");

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
