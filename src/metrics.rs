use prometheus::{GaugeVec, Counter, IntCounter};

lazy_static! {

  pub static ref ACCESS_COUNTER: Counter = register_counter!("openvpn_access_counter", "Requests counter")
    .unwrap();
  pub static ref BYTES_IN: GaugeVec = register_gauge_vec!("openvpn_user_bytes_in", "Bytes in",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon"])
    .expect("can not create gauge openvpn_user_bytes_in");
  pub static ref BYTES_OUT: GaugeVec = register_gauge_vec!("openvpn_user_bytes_out", "Bytes out",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon"])
    .expect("can not create gauge openvpn_user_bytes_out");
  pub static ref DURATION: GaugeVec = register_gauge_vec!("openvpn_user_duration", "Connection duration",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon"])
    .expect("can not create gauge openvpn_user_duration");
  pub static ref RECORD_TIMESTAMP: GaugeVec = register_gauge_vec!("openvpn_user_record_timestamp", "Record timestamp",
    &["session_id", "node", "username", "common_name", "real_ip", "vpn_ip", "location", "lat", "lon"])
    .expect("can not create gauge openvpn_user_record_timestamp");
  // pub static ref USER_COUNT: GaugeVec = register_gauge_vec!("openvpn_user_count", "Number Of Connected Clients",
  //   &["node"])
  //   .expect("can not create gauge openvpn_user_count");
  pub static ref USER_COUNT: IntCounter = register_int_counter!("openvpn_user_count", "Users")
  .unwrap();
}