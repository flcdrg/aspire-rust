var builder = DistributedApplication.CreateBuilder(args);

var rust = builder.AddRustApp("rustwebapi", "../rustwebapi", ["--otel", "--port", "8000"])
    
    .WithHttpEndpoint(port: 8000, isProxied: false)
    .WithExternalHttpEndpoints();

builder.Build().Run();
