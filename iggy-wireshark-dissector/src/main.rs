use bytes::{BufMut, BytesMut};
use iggy_common::get_stats::GetStats;
use iggy_common::ping::Ping;
use server::binary::command::ServerCommand;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Create a complete network packet from ServerCommand
/// Format: [LENGTH (4 bytes)][CODE + PAYLOAD from ServerCommand::to_bytes()]
///
/// This uses the actual ServerCommand enum which properly serializes commands
/// using the same logic as the real Iggy server.
fn create_packet_from_server_command(command: &ServerCommand) -> Vec<u8> {
    // ServerCommand::to_bytes() returns [CODE (4 bytes)][PAYLOAD (N bytes)]
    let command_bytes = command.to_bytes();

    // LENGTH = size of (CODE + PAYLOAD)
    let length = command_bytes.len() as u32;

    // Build complete packet: [LENGTH (4 bytes)][CODE + PAYLOAD]
    let mut bytes = BytesMut::with_capacity(4 + command_bytes.len());
    bytes.put_u32_le(length);
    bytes.put_slice(&command_bytes);

    bytes.to_vec()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Iggy Wireshark Dissector Test ===\n");

    println!("Instructions:");
    println!("1. Install the Lua dissector:");
    println!("   mkdir -p ~/.local/lib/wireshark/plugins/");
    println!("   cp iggy_simple.lua ~/.local/lib/wireshark/plugins/\n");

    println!("2. Start tshark in another terminal:");
    println!("   tshark -i lo0 -f 'tcp port 8090' -Y iggy -V\n");

    println!("3. Start an Iggy server on port 8090, or run this test to send packets\n");

    println!("Press Enter to send test packets to localhost:8090...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Try to connect to Iggy server
    match TcpStream::connect("127.0.0.1:8090").await {
        Ok(mut stream) => {
            println!("Connected to server at 127.0.0.1:8090\n");

            // Send PING command using ServerCommand enum
            let ping_command = ServerCommand::Ping(Ping::default());
            let ping_packet = create_packet_from_server_command(&ping_command);
            println!("Sending PING command:");
            println!("  Total packet: {} bytes", ping_packet.len());
            println!("  Hex: {}\n", hex::encode(&ping_packet));

            stream.write_all(&ping_packet).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Send GET_STATS command using ServerCommand enum
            let stats_command = ServerCommand::GetStats(GetStats::default());
            let stats_packet = create_packet_from_server_command(&stats_command);
            println!("Sending GET_STATS command:");
            println!("  Total packet: {} bytes", stats_packet.len());
            println!("  Hex: {}\n", hex::encode(&stats_packet));

            stream.write_all(&stats_packet).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;

            println!("Packets sent! Check tshark output.");
        }
        Err(e) => {
            println!("Failed to connect to server: {}", e);
            println!("\nYou can still test with packet hexdumps:");

            let ping_command = ServerCommand::Ping(Ping::default());
            let stats_command = ServerCommand::GetStats(GetStats::default());

            let ping_packet = create_packet_from_server_command(&ping_command);
            let stats_packet = create_packet_from_server_command(&stats_command);

            println!("\nPING packet ({} bytes): {}", ping_packet.len(), hex::encode(&ping_packet));
            println!("GET_STATS packet ({} bytes): {}", stats_packet.len(), hex::encode(&stats_packet));

            println!("\nYou can create a PCAP file with these packets for testing.");
        }
    }

    Ok(())
}
