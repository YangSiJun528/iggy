use bytes::{BufMut, BytesMut};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Helper function to create a command packet
fn create_command_packet(code: u32, payload: &[u8]) -> Vec<u8> {
    let length = 4 + payload.len() as u32; // code (4 bytes) + payload
    let mut bytes = BytesMut::with_capacity(8 + payload.len());

    // LENGTH field (4 bytes, little-endian)
    bytes.put_u32_le(length);

    // CODE field (4 bytes, little-endian)
    bytes.put_u32_le(code);

    // PAYLOAD
    bytes.extend_from_slice(payload);

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

            // Send PING command (code: 1)
            let ping_packet = create_command_packet(1, &[]);
            println!("Sending PING command:");
            println!("  LENGTH: 4 (0x04 0x00 0x00 0x00)");
            println!("  CODE: 1 (0x01 0x00 0x00 0x00)");
            println!("  Hex: {}\n", hex::encode(&ping_packet));

            stream.write_all(&ping_packet).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Send GET_STATS command (code: 10)
            let stats_packet = create_command_packet(10, &[]);
            println!("Sending GET_STATS command:");
            println!("  LENGTH: 4 (0x04 0x00 0x00 0x00)");
            println!("  CODE: 10 (0x0a 0x00 0x00 0x00)");
            println!("  Hex: {}\n", hex::encode(&stats_packet));

            stream.write_all(&stats_packet).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;

            println!("Packets sent! Check tshark output.");
        }
        Err(e) => {
            println!("Failed to connect to server: {}", e);
            println!("\nYou can still test with packet hexdumps:");

            let ping_packet = create_command_packet(1, &[]);
            let stats_packet = create_command_packet(10, &[]);

            println!("\nPING packet (8 bytes): {}", hex::encode(&ping_packet));
            println!("GET_STATS packet (8 bytes): {}", hex::encode(&stats_packet));

            println!("\nYou can create a PCAP file with these packets for testing.");
        }
    }

    Ok(())
}
