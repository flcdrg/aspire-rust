use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::OnceLock;

use http_body_util::Full;
use hyper::Method;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use opentelemetry::global::{self, BoxedTracer};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_stdout::SpanExporter;
use serde::Serialize;
use tokio::net::TcpListener;

static OTEL_ENABLED: OnceLock<bool> = OnceLock::new();

fn is_otel_enabled() -> bool {
    *OTEL_ENABLED.get().unwrap_or(&false)
}

#[derive(Serialize)]
struct ApiResponse {
    result: String,
}

async fn api_handler(name: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = ApiResponse {
        result: format!("Hi {}, now with extra Iron Oxide", name),
    };
    let json = serde_json::to_string(&response).unwrap();
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap())
}

async fn handle(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if is_otel_enabled() {
        let tracer = get_tracer();

        let mut span = tracer
            .span_builder(format!("{} {}", req.method(), req.uri().path()))
            .with_kind(SpanKind::Server)
            .start(tracer);

        match (req.method(), req.uri().path()) {
            (&Method::GET, path) if path.starts_with("/api/") => {
                let name = path.strip_prefix("/api/").unwrap_or("");
                if name.is_empty() {
                    span.set_status(Status::Ok);
                    Ok(Response::builder()
                        .status(400)
                        .body(Full::new(Bytes::from(
                            "Bad Request: name parameter required",
                        )))
                        .unwrap())
                } else {
                    api_handler(name).await
                }
            }
            _ => {
                span.set_status(Status::Ok);
                Ok(Response::builder()
                    .status(404)
                    .body(Full::new(Bytes::from("Not Found")))
                    .unwrap())
            }
        }
    } else {
        match (req.method(), req.uri().path()) {
            (&Method::GET, path) if path.starts_with("/api/") => {
                let name = path.strip_prefix("/api/").unwrap_or("");
                if name.is_empty() {
                    Ok(Response::builder()
                        .status(400)
                        .body(Full::new(Bytes::from(
                            "Bad Request: name parameter required",
                        )))
                        .unwrap())
                } else {
                    api_handler(name).await
                }
            }
            _ => Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap()),
        }
    }
}

fn get_tracer() -> &'static BoxedTracer {
    static TRACER: OnceLock<BoxedTracer> = OnceLock::new();
    TRACER.get_or_init(|| global::tracer("dice_server"))
}

fn init_tracer_provider() {
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(SpanExporter::default())
        .build();
    global::set_tracer_provider(provider);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check for command line arguments
    let args: Vec<String> = env::args().collect();
    let otel_enabled = args.contains(&"--otel".to_string());
    OTEL_ENABLED.set(otel_enabled).ok();

    // Parse --port argument
    let mut port = 8080u16;
    for i in 0..args.len() {
        if args[i] == "--port" && i + 1 < args.len() {
            if let Ok(p) = args[i + 1].parse::<u16>() {
                port = p;
            } else {
                eprintln!("Invalid port number: {}", args[i + 1]);
                std::process::exit(1);
            }
            break;
        }
    }

    if otel_enabled {
        init_tracer_provider();
        println!("OpenTelemetry tracing enabled");
    } else {
        println!("OpenTelemetry tracing disabled (use --otel to enable)");
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    // Setup Ctrl-C handler
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\nShutting down...");
        shutdown_tx.send(()).await.ok();
    });

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(handle))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }

    Ok(())
}
