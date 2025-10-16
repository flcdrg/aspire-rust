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
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use opentelemetry_otlp::{WithTonicConfig, WithExportConfig};
use serde::Serialize;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_subscriber::util::SubscriberInitExt;

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
        // Use tracing span for better integration
        let span = tracing::info_span!(
            "http_request",
            method = %req.method(),
            path = %req.uri().path(),
            status_code = tracing::field::Empty,
        );
        let _enter = span.enter();

        match (req.method(), req.uri().path()) {
            (&Method::GET, path) if path.starts_with("/api/") => {
                let name = path.strip_prefix("/api/").unwrap_or("");
                if name.is_empty() {
                    span.record("status_code", 400);
                    tracing::warn!("Bad request: name parameter required");
                    Ok(Response::builder()
                        .status(400)
                        .body(Full::new(Bytes::from(
                            "Bad Request: name parameter required",
                        )))
                        .unwrap())
                } else {
                    let response = api_handler(name).await;
                    span.record("status_code", 200);
                    tracing::info!("Request handled successfully");
                    response
                }
            }
            _ => {
                span.record("status_code", 404);
                tracing::warn!("Not found");
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

fn init_tracer_provider() {
    // Set up trace context propagator for distributed tracing
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Get service name from environment variable
    let service_name = env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "rustwebapi".to_string());
    
    // Create resource with service name using builder pattern
    let resource = Resource::builder()
        .with_service_name(service_name.clone())
        .build();

    // Check if OTEL_EXPORTER_OTLP_ENDPOINT is set
    if let Ok(endpoint) = env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        println!("Using OTLP endpoint: {}", endpoint);
        
        // Check protocol - Aspire may set OTEL_EXPORTER_OTLP_PROTOCOL
        let protocol = env::var("OTEL_EXPORTER_OTLP_PROTOCOL")
            .unwrap_or_else(|_| "grpc".to_string());
        println!("OTLP Protocol: {}", protocol);
        
        // Parse headers - Aspire requires x-otlp-api-key for authentication
        let headers_env = env::var("OTEL_EXPORTER_OTLP_HEADERS").ok();
        if let Some(ref headers) = headers_env {
            println!("OTLP Headers: {}", headers);
        }
        
        // Build the exporter with endpoint and metadata (headers)
        let mut exporter_builder = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&endpoint);
        
        // Parse and add headers if present
        if let Some(headers_str) = headers_env {
            // Parse headers in format "key1=value1,key2=value2" or "key=value"
            let mut metadata = tonic::metadata::MetadataMap::new();
            for header in headers_str.split(',') {
                if let Some((key, value)) = header.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    if let (Ok(metadata_key), Ok(metadata_value)) = (
                        tonic::metadata::MetadataKey::from_bytes(key.as_bytes()),
                        tonic::metadata::MetadataValue::try_from(value)
                    ) {
                        println!("Added header: {}", key);
                        metadata.insert(metadata_key, metadata_value);
                    }
                }
            }
            exporter_builder = exporter_builder.with_metadata(metadata);
        }
        
        let exporter = exporter_builder
            .build()
            .expect("Failed to create OTLP exporter");

        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();
        
        let tracer = provider.tracer(service_name.clone());

        // Set up tracing subscriber with OpenTelemetry integration
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));
        
        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        
        let subscriber = Registry::default()
            .with(env_filter)
            .with(telemetry)
            .with(tracing_subscriber::fmt::layer());
        
        subscriber.init();
        
        // Set the global tracer provider
        let _ = global::set_tracer_provider(provider);
        
    } else {
        // Fallback to stdout exporter if no endpoint is configured
        println!("No OTEL_EXPORTER_OTLP_ENDPOINT found, using stdout exporter");
        
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
            .with_resource(resource)
            .build();

        let tracer = provider.tracer(service_name.clone());

        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));
        
        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        
        let subscriber = Registry::default()
            .with(env_filter)
            .with(telemetry)
            .with(tracing_subscriber::fmt::layer());
        
        subscriber.init();
        
        // Set the global tracer provider
        let _ = global::set_tracer_provider(provider);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check for command line arguments
    let args: Vec<String> = env::args().collect();
    let otel_enabled = args.contains(&"--otel".to_string());
    OTEL_ENABLED.set(otel_enabled).ok();

    // Get service name from environment
    let service_name = env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "rustwebapi".to_string());

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
        println!("OpenTelemetry tracing enabled for service: {}", service_name);
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

    // Shutdown happens automatically when the provider is dropped
    Ok(())
}
