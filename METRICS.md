# OpenTelemetry Metrics

This document describes the OpenTelemetry metrics implemented in the Rust web API.

## Metrics Overview

The application now exports the following metrics to Aspire's OTLP endpoint:

### HTTP Server Metrics

#### `http.server.requests` (Counter)

- **Type**: Counter (u64)
- **Description**: Total number of HTTP requests received
- **Unit**: requests
- **Labels/Attributes**:
  - `method`: HTTP method (GET, POST, etc.)
  - `path`: Request path (e.g., `/api/test`)
  - `status`: HTTP status code (200, 404, 400, etc.)

**Example Usage**: Track request volume, error rates, and traffic patterns by endpoint.

#### `http.server.request.duration` (Histogram)

- **Type**: Histogram (f64)
- **Description**: HTTP request duration in seconds
- **Unit**: seconds (s)
- **Labels/Attributes**:
  - `method`: HTTP method (GET, POST, etc.)
  - `path`: Request path (e.g., `/api/test`)

**Example Usage**: Measure response times, calculate percentiles (p50, p95, p99), and identify slow endpoints.

## Implementation Details

### Architecture

1. **Meter Provider**: `SdkMeterProvider` configured with periodic OTLP exporter
2. **Exporter**: `opentelemetry_otlp::MetricExporter` using gRPC/Tonic transport
3. **Storage**: Metrics instruments stored in `OnceLock` static variables for thread-safe global access
4. **Recording**: Metrics recorded in the `handle()` function for each HTTP request

### Configuration

Metrics are automatically configured when the application starts with the `--otel` flag and the following environment variables are set:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: The OTLP endpoint URL (e.g., `https://localhost:21209`)
- `OTEL_EXPORTER_OTLP_HEADERS`: Authentication headers (e.g., `x-otlp-api-key=<key>`)
- `OTEL_SERVICE_NAME`: Service name for resource attributes (defaults to `rustwebapi`)

### Export Interval

Metrics are exported periodically (default: every 60 seconds) by the `SdkMeterProvider`.

## Viewing Metrics in Aspire

1. **Start the Aspire app**:

   ```powershell
   cd AspireAppHost
   dotnet run
   ```

2. **Access the Aspire dashboard**: Open <https://localhost:17018>

3. **View metrics**:
   - Navigate to the "Metrics" tab
   - Select the `rustwebapi` service
   - View the available metrics:
     - `http.server.requests` - Request counts by method, path, and status
     - `http.server.request.duration` - Request duration histograms

4. **Generate traffic**:

   ```powershell
   # Generate some requests to see metrics
   curl http://localhost:8080/api/test
   curl http://localhost:8080/api/alice
   curl http://localhost:8080/api/bob
   ```

## Metric Examples

### Request Counter

After making requests, you'll see metrics like:

```text
http.server.requests{method="GET", path="/api/test", status="200"} = 5
http.server.requests{method="GET", path="/api/", status="400"} = 2
http.server.requests{method="GET", path="/unknown", status="404"} = 1
```

### Request Duration Histogram

Duration metrics show percentiles:

```text
http.server.request.duration{method="GET", path="/api/test"}
  p50 = 0.001s
  p95 = 0.002s
  p99 = 0.003s
```

## Future Enhancements

Potential metrics to add:

1. **Active Requests**: Track concurrent request count (UpDownCounter)
2. **Response Size**: Measure response body sizes (Histogram)
3. **Custom Business Metrics**: Domain-specific counters or gauges
4. **System Metrics**: CPU, memory, and other runtime metrics
5. **Database Metrics**: Connection pool stats, query durations (if database is added)

## OpenTelemetry Semantic Conventions

The metrics follow [OpenTelemetry Semantic Conventions for HTTP](https://opentelemetry.io/docs/specs/semconv/http/http-metrics/):

- Metric names use the `http.server.*` namespace
- Attributes follow standard naming (e.g., `http.request.method`, simplified here as `method`)
- Units are specified (`requests`, `s` for seconds)
- Descriptions are provided for observability tools

## Code Reference

Key files:

- `src/main.rs`: Metrics initialization and recording logic
- `Cargo.toml`: OpenTelemetry dependencies with metrics feature enabled
