import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import * as nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { MailSendResult, MailSender, MailTransportMode } from './mail.types.js';

const SMTP_SEND_TIMEOUT_MS = 10_000;

/**
 * Nodemailer-backed MailSender. Transport chosen by MAIL_TRANSPORT:
 *  - 'log' (default): the composed message is recorded as ONE structured log
 *    event; no network is attempted. Intended for development.
 *  - 'smtp': a Nodemailer SMTP transport is built from SMTP_* env values and
 *    messages are sent with a bounded timeout. Failures (throw, timeout) are
 *    captured and resolve with delivered:false — never rethrown.
 *
 * Credential hygiene: SMTP mode logs recipient + outcome only; the full link
 * (which contains the opaque token) is logged only in the dev 'log' mode.
 */
@Injectable()
export class NodemailerMailService implements MailSender {
  private readonly logger = new Logger(NodemailerMailService.name);
  private readonly mode: MailTransportMode;
  private readonly from: string;
  private readonly transporter: Transporter | null;

  constructor(configService: ConfigService) {
    const smtpHost = configService.get<string>('SMTP_HOST');
    const explicit = (configService.get<string>('MAIL_TRANSPORT') ?? '').trim();
    // Env-driven: SMTP is enabled when SMTP_HOST is present (unless explicitly
    // forced to 'log'); absent SMTP_* env => email is disabled (log mode).
    this.mode = explicit === 'log' ? 'log' : smtpHost ? 'smtp' : 'log';
    if (smtpHost && explicit === 'log') {
      this.logger.warn(
        'SMTP_HOST set but MAIL_TRANSPORT=log overrides — email disabled',
      );
    }
    this.from =
      configService.get<string>('MAIL_FROM') ?? 'ums-service@localhost';

    if (this.mode === 'smtp') {
      const host = configService.get<string>('SMTP_HOST');
      const port = Number(configService.get<string>('SMTP_PORT') ?? '587');
      const secure =
        (configService.get<string>('SMTP_SECURE') ?? 'false') === 'true';
      const user = configService.get<string>('SMTP_USER') ?? '';
      const pass = configService.get<string>('SMTP_PASSWORD') ?? '';

      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure,
        auth: { user, pass },
      });
    } else {
      this.transporter = null;
    }
    this.mailLogFile = configService.get<string>('MAIL_LOG_FILE') ?? null;
  }

  private readonly mailLogFile: string | null;

  /**
   * Dev/test capture: when MAIL_LOG_FILE is set, append one JSON line per
   * log-transport message. Write failures are captured (warned) — they never
   * break delivery or the caller's response.
   */
  private appendMailLog(entry: Record<string, unknown>): void {
    if (!this.mailLogFile) return;
    try {
      mkdirSync(dirname(this.mailLogFile), { recursive: true });
      appendFileSync(this.mailLogFile, `${JSON.stringify(entry)}\n`);
    } catch (error) {
      this.logger.warn(
        `MAIL_LOG_FILE write failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async sendPasswordReset(
    email: string,
    token: string,
    url: string,
  ): Promise<MailSendResult> {
    const link = `${url}?token=${encodeURIComponent(token)}`;
    const eventPayload = {
      event: 'AUTH_PASSWORD_RESET_REQUESTED',
      recipient: { email },
      template: 'auth-password-reset',
      data: {
        resetUrl: link,
        token,
        expiresInMinutes: 60,
      },
    };

    this.logger.log({
      action: 'mail.outbox-dispatch',
      ...eventPayload,
    });

    const subject = 'Reset your password';
    const text = `You requested a password reset. Open this link:\n${link}`;
    const html = `<p>You requested a password reset: <a href="${link}">${link}</a></p>`;
    return this.deliver(email, subject, text, html, link);
  }

  async sendEmailVerification(
    email: string,
    token: string,
    url: string,
  ): Promise<MailSendResult> {
    const link = `${url}?token=${encodeURIComponent(token)}`;
    const eventPayload = {
      event: 'AUTH_EMAIL_VERIFICATION_REQUESTED',
      recipient: { email },
      template: 'auth-email-verification',
      data: {
        verifyUrl: link,
        token,
        expiresInHours: 24,
      },
    };

    this.logger.log({
      action: 'mail.outbox-dispatch',
      ...eventPayload,
    });

    const subject = 'Verify your email';
    const text = `Confirm your email by opening this link:\n${link}`;
    const html = `<p>Confirm your email: <a href="${link}">${link}</a></p>`;
    return this.deliver(email, subject, text, html, link);
  }

  private async deliver(
    to: string,
    subject: string,
    text: string,
    html: string,
    link: string,
  ): Promise<MailSendResult> {
    try {
      if (this.mode === 'log' || !this.transporter) {
        // Dev transport: one structured log event carries the full message.
        const entry = {
          event: 'mail.log-transport',
          transport: 'log',
          to,
          subject,
          link,
          at: new Date().toISOString(),
        };
        this.logger.log(entry);
        this.appendMailLog(entry);
        return { delivered: true, transport: 'log' };
      }

      await Promise.race([
        this.transporter.sendMail({
          from: this.from,
          to,
          subject,
          text,
          html,
        }),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error('SMTP send timed out')),
            SMTP_SEND_TIMEOUT_MS,
          ),
        ),
      ]);

      // smtp mode: recipient + outcome only — the token-bearing link is not logged.
      this.logger.log({ event: 'mail.sent', transport: 'smtp', to, subject });
      return { delivered: true, transport: 'smtp' };
    } catch (error) {
      this.logger.error({
        event: 'mail.failed',
        transport: this.mode,
        to,
        subject,
        error: error instanceof Error ? error.message : String(error),
      });
      return { delivered: false, transport: this.mode };
    }
  }
}
