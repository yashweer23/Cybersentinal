# Performance measurements and interpretation

[Testing commands](TESTING.md) · [Phase 16 report](PHASE16_VALIDATION.md) · [Phase 17 verification](PHASE17_VALIDATION.md)

These are dated local measurements, not production capacity or service-level guarantees. All runs used seed 42, mixed synthetic scenarios, no live intelligence/LLM calls and one database connection in an embedded PostgreSQL-compatible runtime. The Phase 16 engine was PGlite PostgreSQL 17.5; the fresh Phase 17 screenshot run used PGlite 0.5.10 / PostgreSQL 18.6. The application Docker target remains PostgreSQL 17. Different runtimes and sampling conditions prevent treating the difference as an optimization result.

## Pipeline timings

Wall time includes the measured stage. Throughput is event count divided by its wall time. Native PostgreSQL concurrency requires separate measurement.

| Run | Events | Ingest ms | Ingest events/s | Detect ms | Detect events/s | Findings | Cases |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Phase 16 | 1,000 | 496.522 | 2,014.01 | 364.888 | 2,740.57 | 6 | 5 |
| Phase 16 | 10,000 | 5,500.269 | 1,818.09 | 13,663.183 | 731.89 | 36 | 29 |
| Phase 17 | 10,000 | 5,332.312 | 1,875.36 | 11,052.652 | 904.76 | 36 | 29 |

Both Phase 16 sizes and the Phase 17 10k run verified zero pending events, valid evidence references and repeat processing without duplicate growth. The full backend suite was recorded in Phase 16; it was not rerun wholesale for this documentation-only/domain-unchanged update.

## Authenticated HTTP read-load: recorded Phase 16

Apache JMeter 5.6.3 used loopback TCP, nine read endpoints, 100 ms think time and a 5-second ramp. One temporary identity was shared by virtual readers. These short read-load tests are not mixed-write workloads or endurance tests.

| Users | Scheduled seconds | Measured seconds | Requests | Errors | Requests/s | Mean ms | p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 30 | 29.363 | 2,027 | 0 | 69.032 | 36.035 | 77.0 |
| 25 | 60 | 59.615 | 4,956 | 0 | 83.133 | 190.219 | 337.0 |

p95 uses the nearest-rank sample definition. Serial TestClient timing includes serialization/application/database work but does not include a network round trip; do not mix it with JMeter TCP timings. Full endpoint results and retained load samples are linked in [phase16_results.json](phase16_results.json).

## Synthetic evaluation

The 10k dataset produced 36 covered scenario/rule units out of 37 expected, with no unexpected labeled findings. Scenario recall is 36/37 = 97.30%; finding label agreement is 100%. **Precision is intentionally not reported**: retained labeled evidence and overlapping behaviors do not establish the set of real false positives. The generator's 500-event suspicious budget omitted its large API scenario, and one access-denied episode had fewer events than the configured threshold. All ten rules executed; individual tests cover CS-010.

Capture-time chart totals can differ from retained totals because rolling date windows exclude the beginning of a midnight-aligned generated week. This is a range definition, not dropped ingestion. Native database/query planning, simultaneous writers, container restart and backup/restore are still acceptance gates. See [TESTING.md](TESTING.md).
