import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { appendFileSync } from 'node:fs';
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
  private readonly logFile: string | null;

  constructor(configService: ConfigService) {
    const rawMode = (
      configService.get<string>('MAIL_TRANSPORT') ?? 'log'
    ).trim();
    this.mode = rawMode === 'smtp' ? 'smtp' : 'log';
    if (rawMode !== 'log' && rawMode !== 'smtp') {
      this.logger.warn(
        `MAIL_TRANSPORT value '${rawMode}' is unknown — falling back to 'log'`,
      );
    }
    this.from =
      configService.get<string>('MAIL_FROM') ?? 'ums-service@localhost';
    this.logFile = configService.get<string>('MAIL_LOG_FILE')?.trim() || null;

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
  }

  async sendPasswordReset(
    email: string,
    token: string,
    url: string,
  ): Promise<MailSendResult> {
    const subject = 'Reset your password';
    const link = `${url}?token=${encodeURIComponent(token)}`;
    const text = `You requested a password reset. Open this link to choose a new password (valid for the configured TTL):\n${link}\n\nIf you did not request this, you can ignore this email.`;
    const html = `<p>You requested a password reset.</p><p><a href="${link}">Choose a new password</a></p><p>If you did not request this, you can ignore this email.</p>`;
    return this.deliver(email, subject, text, html, link);
  }

  async sendEmailVerification(
    email: string,
    token: string,
    url: string,
  ): Promise<MailSendResult> {
    const subject = 'Verify your email';
    const link = `${url}?token=${encodeURIComponent(token)}`;
    const text = `Confirm your email address by opening this link (valid for the configured TTL):\n${link}\n\nIf you did not register, you can ignore this email.`;
    const html = `<p>Welcome!</p><p><a href="${link}">Verify your email</a></p><p>If you did not register, you can ignore this email.</p>`;
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
        this.logger.log({
          event: 'mail.log-transport',
          transport: 'log',
          to,
          subject,
          link,
        });
        if (this.logFile) {
          // Optional sink for E2E tests: same JSON line, appended one per send.
          try {
            appendFileSync(
              this.logFile,
              `${JSON.stringify({ event: 'mail.log-transport', transport: 'log', to, subject, link })}\n`,
            );
          } catch (fileError) {
            this.logger.warn({
              event: 'mail.log-file-failed',
              file: this.logFile,
              error:
                fileError instanceof Error
                  ? fileError.message
                  : String(fileError),
            });
          }
        }
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
