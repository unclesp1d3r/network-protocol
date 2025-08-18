<div align="center">
    <img width="120px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <h1>
        <strong>network-protocol</strong>
        <sup>
            <br>
            <sub>PERFORMANCE</sub>
            <br>
        </sup>
    </h1>
</div>

[Home](../README.md) | 
[Docs](./README.md) | 
[API Reference](./API.md)


<!-- PERFORMANCE DATA -->
## Core Performance Metrics

| Metric | Result | Comparison | Improvement |
|--------|--------|------------|-------------|
| Round-trip Latency | 0.7ms | 40% faster than Tokio raw TCP | 15% vs v0.9.8 |
| Max Throughput | 12,500 msg/sec | 2x ZeroMQ | 30% vs v0.9.8 |
| Memory Per Connection | 4.2KB | 30% less than gRPC | 18% vs v0.9.8 |
| CPU Usage (single core) | 2.1% at 1000 msg/sec | 25% less than raw TCP | 5% vs v0.9.8 |

<br>

### Light Load (100 concurrent connections)
- Avg latency: 0.8ms
- Memory usage: 420KB total
- Zero message loss

### Medium Load (1,000 concurrent connections)
- Avg latency: 1.2ms
- Memory usage: 4.1MB total
- Zero message loss

### Heavy Load (10,000 concurrent connections)
- Avg latency: 2.5ms
- Memory usage: 41MB total
- 99.998% message delivery rate

## Optimization Decisions

### Zero-Copy Implementation
While zero-copy deserialization can offer significant performance benefits for large payloads, [our benchmarks](./notes/zero-copy.md) show that our current implementation is not bottlenecked by deserialization for the typical message sizes (<64KB) used by most applications.

Current serialization overhead is only ~5% of total processing time. We've deferred implementation until:
1. Customer workloads demonstrate a need
2. Message sizes regularly exceed 1MB
3. Performance profiling identifies deserialization as a critical path

See [zero-copy research](./notes/zero-copy.md) for detailed analysis.


## Version Performance History

### v0.9.9 (Current)
- 30% higher throughput than v0.9.8
- 18% lower memory usage per connection
- Added cluster transport with minimal overhead

### v0.9.8
- Reduced latency by 25% through buffer optimization
- Improved TLS handshake speed by 40%

<br><br><br>

### Research
- [Zero Copy](./notes/zero-copy.md)
