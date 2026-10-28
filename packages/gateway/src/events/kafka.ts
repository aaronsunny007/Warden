/** Kafka sink (Apache Kafka in KRaft mode, or Redpanda). Keyed by session so a session's events stay ordered. */
import { Producer, stringSerializers } from '@platformatic/kafka';
import type { EventSink } from './bus.js';
import type { WardenEvent } from './types.js';

export class KafkaSink implements EventSink {
  name = 'kafka';
  private producer: Producer<string, string, string, string>;

  constructor(
    brokers: string[],
    private topic: string,
    clientId: string,
  ) {
    this.producer = new Producer({
      clientId,
      bootstrapBrokers: brokers,
      serializers: stringSerializers,
      autocreateTopics: true,
    });
  }

  async publish(events: WardenEvent[]): Promise<void> {
    await this.producer.send({
      messages: events.map((e) => ({
        topic: this.topic,
        key: ((e.data as { sessionId?: string })?.sessionId ?? e.type).slice(0, 128),
        value: JSON.stringify(e),
        headers: { type: e.type },
      })),
    });
  }

  async close(): Promise<void> {
    await this.producer.close();
  }
}
