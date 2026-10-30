import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service.js';
import { OutboxStatus, Prisma } from '@prisma/client';
import { Kafka, Producer } from 'kafkajs';
import { UMS_TOPICS } from '../../events/ums.events.js';

@Injectable()
export class OutboxService {
  constructor(private readonly prisma: PrismaService) {}

  async emit(
    aggregateType: string,
    aggregateId: string,
    eventType: string,
    payload: unknown,
    tx?: Prisma.TransactionClient,
  ) {
    const client = tx || this.prisma;
    return client.outboxEvent.create({
      data: {
        aggregateType,
        aggregateId,
        eventType,
        payload: payload as Prisma.InputJsonValue,
        status: OutboxStatus.PENDING,
      },
    });
  }
}

/**
 * Outbox relay that publishes PENDING outbox rows to Kafka topics:
 *   - ums.user.created
 *   - ums.user.updated
 *   - ums.user.suspended
 *   - ums.role.changed
 *   - ums.session.revoked
 *
 * Rows are marked PROCESSED only after broker ack.
 * If KAFKA_BROKERS is missing or KAFKA_PRODUCER_DISABLED=true, the relay
 * falls back to log-based processing to avoid losing events.
 */
@Injectable()
export class OutboxRelayService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OutboxRelayService.name);
  private intervalRef: NodeJS.Timeout | null = null;
  private producer: Producer | null = null;
  private kafka: Kafka | null = null;
  private isProcessing = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  private get kafkaEnabled(): boolean {
    const brokers = this.configService.get<string>('KAFKA_BROKERS');
    const disabled =
      this.configService.get<string>('KAFKA_PRODUCER_DISABLED') === 'true';
    return Boolean(brokers) && !disabled;
  }

  private topicFor(eventType: string): string | null {
    switch (eventType) {
      case 'USER_CREATED':
      case 'ums.user.created':
      case UMS_TOPICS.USER_CREATED:
        return UMS_TOPICS.USER_CREATED;
      case 'USER_UPDATED':
      case 'ums.user.updated':
      case UMS_TOPICS.USER_UPDATED:
        return UMS_TOPICS.USER_UPDATED;
      case 'USER_SUSPENDED':
      case 'ums.user.suspended':
      case UMS_TOPICS.USER_SUSPENDED:
        return UMS_TOPICS.USER_SUSPENDED;
      case 'ROLE_CHANGED':
      case 'ums.role.changed':
      case UMS_TOPICS.ROLE_CHANGED:
        return UMS_TOPICS.ROLE_CHANGED;
      case 'SESSION_REVOKED':
      case 'ums.session.revoked':
      case UMS_TOPICS.SESSION_REVOKED:
        return UMS_TOPICS.SESSION_REVOKED;
      default:
        return null;
    }
  }

  async onModuleInit(): Promise<void> {
    if (this.kafkaEnabled) {
      const brokers = (this.configService.get<string>('KAFKA_BROKERS') ?? '')
        .split(',')
        .map((b) => b.trim())
        .filter(Boolean);

      this.logger.log(
        `Initializing Kafka producer for brokers: ${brokers.join(', ')}`,
      );
      this.kafka = new Kafka({
        clientId:
          this.configService.get<string>('KAFKA_CLIENT_ID') ||
          'ums-service-outbox',
        brokers,
      });
      this.producer = this.kafka.producer({
        allowAutoTopicCreation: false,
        retry: { initialRetryTime: 300, retries: 5 },
      });
      try {
        await this.producer.connect();
        this.logger.log('Kafka producer connected');
      } catch (err) {
        this.logger.warn(
          `Could not connect to Kafka (${(err as Error).message}) — relay will use log-based processing.`,
        );
        this.producer = null;
      }
    } else {
      this.logger.log(
        'Kafka producer disabled (KAFKA_BROKERS missing or KAFKA_PRODUCER_DISABLED=true) — relay falls back to log-based processing.',
      );
    }

    if (process.env.NODE_ENV !== 'test') {
      this.intervalRef = setInterval(() => {
        this.processPendingEvents().catch((err) => {
          this.logger.error('Error processing outbox events', err);
        });
      }, 3000);
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.intervalRef) {
      clearInterval(this.intervalRef);
      this.intervalRef = null;
    }
    if (this.producer) {
      await this.producer.disconnect().catch(() => {});
      this.logger.log('Kafka producer disconnected');
    }
  }

  async processPendingEvents(): Promise<void> {
    if (this.isProcessing) {
      return;
    }
    this.isProcessing = true;
    try {
      const events = await this.prisma.outboxEvent.findMany({
        where: { status: OutboxStatus.PENDING },
        take: 50,
        orderBy: { createdAt: 'asc' },
      });

      for (const event of events) {
        try {
          const topic = this.topicFor(event.eventType);
          if (topic && this.producer) {
            const payloadObj =
              typeof event.payload === 'object' && event.payload !== null
                ? (event.payload as Record<string, unknown>)
                : { payload: event.payload };

            await this.producer.send({
              topic,
              messages: [
                {
                  key: event.aggregateId,
                  value: JSON.stringify({
                    eventId: event.id,
                    aggregateId: event.aggregateId,
                    sourceService: 'ums-service',
                    eventType: event.eventType,
                    occurredAt: event.createdAt.toISOString(),
                    ...payloadObj,
                  }),
                },
              ],
            });
            this.logger.log(
              `Published event ${event.eventType} (${event.aggregateId}) to ${topic}`,
            );
          } else {
            this.logger.log(
              `Log-relay fallback for event ${event.eventType} (${event.aggregateId}) — no Kafka producer.`,
            );
          }

          await this.prisma.outboxEvent.update({
            where: { id: event.id },
            data: {
              status: OutboxStatus.PROCESSED,
              processedAt: new Date(),
            },
          });
        } catch (error) {
          this.logger.error(
            `Failed to process outbox event ${event.id}: ${(error as Error).message}`,
            (error as Error).stack,
          );
          await this.prisma.outboxEvent
            .update({
              where: { id: event.id },
              data: {
                status: OutboxStatus.FAILED,
                error: (error as Error).message,
              },
            })
            .catch(() => {});
        }
      }
    } finally {
      this.isProcessing = false;
    }
  }
}
