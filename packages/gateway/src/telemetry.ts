/** OpenTelemetry tracing, enabled only when an OTLP endpoint is configured. */
export async function initTelemetry(endpoint: string, serviceName: string): Promise<() => Promise<void>> {
  if (!endpoint) return async () => undefined;
  const { NodeSDK } = await import('@opentelemetry/sdk-node');
  const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-http');
  process.env.OTEL_SERVICE_NAME ??= serviceName;
  const sdk = new NodeSDK({
    traceExporter: new OTLPTraceExporter({ url: `${endpoint.replace(/\/$/, '')}/v1/traces` }),
  });
  sdk.start();
  return () => sdk.shutdown();
}
