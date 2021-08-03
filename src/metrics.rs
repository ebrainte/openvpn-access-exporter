use prometheus::{GaugeVec, Counter};

lazy_static! {

  pub static ref ACCESS_COUNTER: Counter = register_counter!("access_counter", "Requests counter")
    .unwrap();
  pub static ref BYTES_IN: GaugeVec = register_gauge_vec!("openvpn_user_bytes_in", "Bytes in",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon", "mac_address"])
    .expect("can not create gauge openvpn_user_bytes_in");
  pub static ref BYTES_OUT: GaugeVec = register_gauge_vec!("openvpn_user_bytes_out", "Bytes out",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon", "mac_address"])
    .expect("can not create gauge openvpn_user_bytes_out");
  pub static ref DURATION: GaugeVec = register_gauge_vec!("openvpn_user_duration", "Connection duration",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon", "mac_address"])
    .expect("can not create gauge openvpn_user_duration");
  pub static ref RECORD_TIMESTAMP: GaugeVec = register_gauge_vec!("openvpn_user_record_timestamp", "Record timestamp",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon", "mac_address"])
    .expect("can not create gauge openvpn_user_record_timestamp");
  pub static ref CROWDSTRIKE_INSTALLED: GaugeVec = register_gauge_vec!("openvpn_user_crowdstrike_installed", "Crowdstrike installation flag (-1 unknown, 0 not installed, 1 installed)",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon", "mac_address"])
    .expect("can not create gauge openvpn_user_crowdstrike_installed");
  pub static ref CROWDSTRIKE_LAST_SEEN_TIMESTAMP: GaugeVec = register_gauge_vec!("openvpn_user_crowdstrike_last_seen_timestamp", "Crowdstrike last seen timestamp",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon", "mac_address"])
    .expect("can not create gauge openvpn_user_crowdstrike_last_seen_timestamp");
  pub static ref CROWDSTRIKE_LAST_CHECK_TIMESTAMP: GaugeVec = register_gauge_vec!("openvpn_user_crowdstrike_last_check_timestamp", "Timestamp of last check of crowdstrike installation",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon", "mac_address"])
    .expect("can not create gauge openvpn_user_crowdstrike_last_check_timestamp");
}
