// Will create an exporter with a single metric that will randomize the value
// of the metric everytime the exporter is called.

#[macro_use] extern crate prometheus;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;

use env_logger::{
    Builder,
    Env
};

use clap::{App, Arg};
use prometheus::{TextEncoder, Encoder};
use hyper::{header::CONTENT_TYPE, rt::Future, service::service_fn_ok, Body, Response, Server};
use std::net::SocketAddr;
use sqlite::State;
use std::net::IpAddr;
use maxminddb::geoip2;

mod metrics;

fn main() {
    let flags = App::new("openvpn-access-exporter")
        .version("0.1")
        .about("Prometheus exporter for OpenVPN Access Server")
        .author("Luis Felipe Domínguez Vega <ldominguezvega@gmail.com>")
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .help("SQLite log file (log.db)")
            .required(true)
            .takes_value(true)
        )
        .arg(Arg::with_name("userpropfile")
            .short("u")
            .long("userpropfile")
            .help("SQLite userprop file (userprop.db)")
            .required(true)
            .takes_value(true)
        )
        .arg(Arg::with_name("ldapfile")
            .short("l")
            .long("ldapfile")
            .help("SQLite LDAP file (ldap.db)")
            .required(true)
            .takes_value(true)
        )
        .arg(Arg::with_name("geofile")
            .short("g")
            .long("geofile")
            .help("GeoLite2 City file (GeoLite2-City.mmdb)")
            .required(true)
            .takes_value(true)
        )
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .help("Host port to expose http server")
            .required(false)
            .takes_value(true)
            .default_value("9185")
        )
        .arg(Arg::with_name("host")
            .short("h")
            .long("host")
            .help("Address where to expose http server")
            .required(false)
            .takes_value(true)
            .default_value("0.0.0.0")
        )
        .get_matches();

    let expose_port = flags.value_of("port").unwrap();
    let expose_host = flags.value_of("host").unwrap();

    // Setup logger with default level info so we can see the messages from
    // prometheus_exporter.
    Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Using file: {}", flags.value_of("file").unwrap());
    info!("Using userpropfile: {}", flags.value_of("userpropfile").unwrap());
    info!("Using ldapfile: {}", flags.value_of("ldapfile").unwrap());
    info!("Using geofile: {}", flags.value_of("geofile").unwrap());

    // Parse address used to bind exporter to.
    let addr_raw = expose_host.to_owned() + ":" + expose_port;
    let addr: SocketAddr = addr_raw.parse().expect("can not parse listen addr");

    // Need to clone before moving to closure. 
    // Ref.: https://stackoverflow.com/a/67697017/1003873
    let flags = flags.clone();

    let new_service = move || {
      let ovpn_log = flags.value_of("file").unwrap();
      let ovpn_ldap = flags.value_of("ldapfile").unwrap();

      let encoder = TextEncoder::new();
      let connection = sqlite::open(&ovpn_log).unwrap();
      let connection_ldap = sqlite::open(&ovpn_ldap).unwrap();

      // Need to clone before moving to closure. 
      // Ref.: https://stackoverflow.com/a/67697017/1003873
      let flags = flags.clone();

      service_fn_ok(move |_request| {
        //let flags = flags.clone();
        let ovpn_geo = flags.value_of("geofile").unwrap();
        let ovpn_userprop = flags.value_of("userpropfile").unwrap();

        info!("Using geofile: {}", &ovpn_geo);

        metrics::ACCESS_COUNTER.inc();
        let georeader =  maxminddb::Reader::open_readfile(&ovpn_geo).unwrap();
        
        // Attaching userprop database to allow join between logs and user properties
        let mut attach_statement = connection
          .prepare("ATTACH ? AS userpropdb")
          .unwrap();

        attach_statement.bind(1, ovpn_userprop).unwrap();

        // Assumes session older than 24 hours are not active anymore (since active flag is not always updated properly)
        let mut statement = connection
            .prepare("SELECT l.session_id, l.node, l.username, l.common_name, l.real_ip, l.vpn_ip, l.duration, l.bytes_in, l.bytes_out, l.timestamp, (SELECT c.value FROM userpropdb.profile p, userpropdb.config c WHERE c.profile_id = p.id AND c.name = 'crowdstrike_installed' AND lower(p.name) = lower(l.username)), (SELECT c.value FROM userpropdb.profile p, userpropdb.config c WHERE c.profile_id = p.id AND c.name = 'crowdstrike_last_seen' AND lower(p.name) = lower(l.username)), (SELECT c.value FROM userpropdb.profile p, userpropdb.config c WHERE c.profile_id = p.id AND c.name = 'crowdstrike_last_check' AND lower(p.name) = lower(l.username)), (SELECT c.value FROM userpropdb.profile p, userpropdb.config c WHERE c.profile_id = p.id AND c.name = 'pvt_hw_addr' AND lower(p.name) = lower(l.username)) FROM log l WHERE l.active = 1 and l.auth = 1 and l.start_time >= strftime('%s', datetime('now','-1 days'))")
            .unwrap();
        while let State::Row = statement.next().unwrap() {
          let ip: IpAddr = statement.read::<String>(4).unwrap().parse().unwrap();
          
          // Find location associated with IP
          let city: std::result::Result<Option<geoip2::City>, maxminddb::MaxMindDBError> = georeader.lookup(ip);
          let (c_name, lat, lon) = match city {
            Ok(Some(city)) => (
              city.city.and_then(|cy| cy.names)
                       .and_then(|n| n.get("en")
                       .map(String::from)),
              city.location.as_ref().unwrap().latitude.unwrap(),
              city.location.as_ref().unwrap().longitude.unwrap()
             ),
             _ => (Some("unknown".to_owned()), 0.0_f64, 0.0_f64),
          };

          let timestamp_ms = statement.read::<i64>(9).unwrap() * 1000;
          let username = statement.read::<String>(2);

          // Find user full name from ldap database
          let mut statement_ldap = connection_ldap
              .prepare("SELECT cn from users where upper(uid) = upper(?)")
              .unwrap();

          statement_ldap.bind(1, &username.as_ref().unwrap()[..]).unwrap();

          let mut fullname = "Unknown".to_string();
          while let State::Row = statement_ldap.next().unwrap() {
            fullname = statement_ldap.read::<String>(0).unwrap();
          }

          let label_values = [
            &statement.read::<String>(0).unwrap()[..], 
            &statement.read::<String>(1).unwrap()[..],
            &statement.read::<String>(2).unwrap()[..],
            &fullname,
            &statement.read::<String>(4).unwrap()[..],
            &statement.read::<String>(5).unwrap()[..],
            &c_name.unwrap_or("None".to_string()),
            &lat.to_string(),
            &lon.to_string(),
            &statement.read::<String>(10).unwrap()[..],
            &statement.read::<String>(11).unwrap()[..],
            &statement.read::<String>(12).unwrap()[..],
            &statement.read::<String>(13).unwrap()[..]
          ];

          metrics::DURATION.with_label_values(&label_values).set(statement.read::<f64>(6).unwrap());
          metrics::BYTES_IN.with_label_values(&label_values).set(statement.read::<f64>(7).unwrap());
          metrics::BYTES_OUT.with_label_values(&label_values).set(statement.read::<f64>(8).unwrap());
          metrics::RECORD_TIMESTAMP.with_label_values(&label_values).set(timestamp_ms as f64);

          metrics::DURATION.with_label_values(&label_values);
          metrics::BYTES_IN.with_label_values(&label_values);
          metrics::BYTES_OUT.with_label_values(&label_values);
          metrics::RECORD_TIMESTAMP.with_label_values(&label_values);
        }

        // Gather the metrics.
        let mut buffer = vec![];
        let metric_families = prometheus::gather();

        encoder.encode(&metric_families, &mut buffer).unwrap();

        Response::builder()
          .status(200)
          .header(CONTENT_TYPE, encoder.format_type())
          .body(Body::from(buffer))
          .unwrap()
      })
    };

    let server = Server::bind(&addr)
      .serve(new_service)
      .map_err(|e| eprintln!("Server error: {}", e));

    hyper::rt::run(server);
}
