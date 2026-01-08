use alpine::e2e_common::run_udp_handshake;
use std::error::Error;

#[tokio::test]
#[ignore = "UDP E2E test; run explicitly when environment is ready"]
async fn handshake_udp_e2e_phase1() -> Result<(), Box<dyn Error>> {
    let (controller_session, node_session) = run_udp_handshake().await?;

    let controller_established = controller_session
        .established()
        .ok_or("controller missing established state")?;
    let node_established = node_session
        .established()
        .ok_or("node missing established state")?;

    assert_eq!(
        controller_established.session_id,
        node_established.session_id
    );

    let controller_keys = controller_session.keys().ok_or("controller missing keys")?;
    let node_keys = node_session.keys().ok_or("node missing keys")?;
    assert_eq!(controller_keys.control_key, node_keys.control_key);
    assert_eq!(controller_keys.stream_key, node_keys.stream_key);

    Ok(())
}
