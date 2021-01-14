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

    //let ovpn_log = flags.value_of("file").unwrap();
    //let ovpn_log = format!("{}", flags.value_of("file").unwrap())[..];
    let expose_port = flags.value_of("port").unwrap();
    let expose_host = flags.value_of("host").unwrap();

    // Setup logger with default level info so we can see the messages from
    // prometheus_exporter.
    Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Using file: {}", flags.value_of("file").unwrap());

    // Parse address used to bind exporter to.
    let addr_raw = expose_host.to_owned() + ":" + expose_port;
    let addr: SocketAddr = addr_raw.parse().expect("can not parse listen addr");

    let new_service = move || {
      let ovpn_log = flags.value_of("file").unwrap();

      let encoder = TextEncoder::new();
      let connection = sqlite::open(&ovpn_log).unwrap();

      service_fn_ok(move |_request| {

        metrics::ACCESS_COUNTER.inc();
        let georeader =  maxminddb::Reader::open_readfile("/usr/share/geoip/GeoLite2-City.mmdb").unwrap();

        let mut statement = connection
            .prepare("SELECT session_id, node, username, common_name, real_ip, vpn_ip, duration, bytes_in, bytes_out, timestamp FROM log WHERE active = 1")
            .unwrap();
        while let State::Row = statement.next().unwrap() {
          let ip: IpAddr = statement.read::<String>(4).unwrap().parse().unwrap();
          
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

          let label_values = [
            &statement.read::<String>(0).unwrap()[..],
            &statement.read::<String>(1).unwrap()[..],
            &statement.read::<String>(2).unwrap()[..],
            &statement.read::<String>(3).unwrap()[..],
            &statement.read::<String>(4).unwrap()[..],
            &statement.read::<String>(5).unwrap()[..],
            &c_name.unwrap_or("None".to_string()),
            &lat.to_string(),
            &lon.to_string()
          ];

          metrics::DURATION.with_label_values(&label_values).set(statement.read::<f64>(6).unwrap());
          metrics::BYTES_IN.with_label_values(&label_values).set(statement.read::<f64>(7).unwrap());
          metrics::BYTES_OUT.with_label_values(&label_values).set(statement.read::<f64>(8).unwrap());

          metrics::DURATION.with_label_values(&label_values);
          metrics::BYTES_IN.with_label_values(&label_values);
          metrics::BYTES_OUT.with_label_values(&label_values);
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
