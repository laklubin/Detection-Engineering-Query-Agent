/**
 * API client.
 *
 * Holds the session bearer token and bound CSRF value in memory only — never in
 * localStorage, sessionStorage or a cookie — so the credential cannot be read
 * by another script after a refresh and cannot be replayed cross-site.
 *
 * There is no Hugging Face token in the frontend. The browser only ever talks
 * to the project's own Worker.
 */

import type { ErrorResponse, GenerateRequest, GenerateResponse } from '@detectionforge/core';

export interface CatalogVendor {
  id: string;
  name: string;
  description: string;
}

export interface CatalogLogSource {
  id: string;
  name: string;
  vendorId: string;
  telemetry: string;
  keywords: string[];
}

export interface CatalogPlatform {
  id: string;
  product: string;
  language: string;
  highlight: string;
  fileExtension: string;
  standaloneQueryIsDeployable: boolean;
  notes: string;
}

export interface Catalog {
  vendors: CatalogVendor[];
  logSources: CatalogLogSource[];
  platforms: CatalogPlatform[];
  limits: { requirementMinChars: number; requirementMaxChars: number; maxUseCasesPerRequest: number };
  notices: { commercial: string; offTopicRejection: string; validationDisclaimer: string };
}

export interface Health {
  mode: 'live' | 'demo';
  model: string | null;
  promptVersion: string;
  authenticationConfigured: boolean;
  rateLimitDurable: boolean;
  supportedPlatforms: number;
  maxUseCasesPerRequest: number;
}

export class ApiError extends Error {
  readonly code: string;
  readonly details: string[];
  readonly retryAfterSeconds?: number;
  readonly httpStatus: number;

  constructor(
    code: string,
    message: string,
    options: { details?: string[]; retryAfterSeconds?: number; httpStatus?: number } = {},
  ) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.details = options.details ?? [];
    if (options.retryAfterSeconds !== undefined) this.retryAfterSeconds = options.retryAfterSeconds;
    this.httpStatus = options.httpStatus ?? 0;
  }
}

interface SessionState {
  token: string;
  csrfToken: string;
  expiresAt: number;
}

const DEFAULT_TIMEOUT_MS = 60_000;

export class DetectionForgeApi {
  private session: SessionState | null = null;

  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = (...args) => fetch(...args),
  ) {}

  get configured(): boolean {
    return this.baseUrl.trim().length > 0;
  }

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/+$/, '')}${path}`;
  }

  private async send(path: string, init: RequestInit = {}, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await this.fetchImpl(this.url(path), { ...init, signal: controller.signal });
      const text = await response.text();
      let payload: unknown = null;
      if (text.length > 0) {
        try {
          payload = JSON.parse(text);
        } catch {
          payload = null;
        }
      }
      if (!response.ok) {
        const error = payload as Partial<ErrorResponse> | null;
        throw new ApiError(error?.code ?? 'internal_error', error?.message ?? `Request failed (HTTP ${response.status}).`, {
          details: error?.details ? [...error.details] : [],
          ...(error?.retryAfterSeconds !== undefined ? { retryAfterSeconds: error.retryAfterSeconds } : {}),
          httpStatus: response.status,
        });
      }
      return payload;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if ((error as { name?: string }).name === 'AbortError') {
        throw new ApiError('upstream_timeout', 'The request to the detection API timed out.');
      }
      throw new ApiError(
        'network_error',
        'The detection API could not be reached. Check that the backend is deployed and that this origin is on its CORS allowlist.',
      );
    } finally {
      clearTimeout(timer);
    }
  }

  async health(): Promise<Health> {
    return (await this.send('/api/v1/health', { method: 'GET' }, 15_000)) as Health;
    }

  async catalog(): Promise<Catalog> {
    return (await this.send('/api/v1/catalog', { method: 'GET' }, 15_000)) as Catalog;
  }

  private async ensureSession(): Promise<SessionState> {
    if (this.session && this.session.expiresAt - 30_000 > Date.now()) return this.session;
    const payload = (await this.send('/api/v1/session', { method: 'POST' }, 15_000)) as {
      token: string;
      csrfToken: string;
      expiresAt: string;
    };
    this.session = {
      token: payload.token,
      csrfToken: payload.csrfToken,
      expiresAt: Date.parse(payload.expiresAt),
    };
    return this.session;
  }

  async generate(request: GenerateRequest): Promise<GenerateResponse> {
    let session = await this.ensureSession();
    const call = async (current: SessionState): Promise<unknown> =>
      this.send('/api/v1/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${current.token}`,
          'X-DFAI-CSRF': current.csrfToken,
        },
        body: JSON.stringify(request),
      });

    try {
      return (await call(session)) as GenerateResponse;
    } catch (error) {
      // A single transparent retry when the session expired mid-flight.
      if (error instanceof ApiError && error.httpStatus === 401) {
        this.session = null;
        session = await this.ensureSession();
        return (await call(session)) as GenerateResponse;
      }
      throw error;
    }
  }

  /** Drop the in-memory credential. Called by the Clear action. */
  forgetSession(): void {
    this.session = null;
  }
}
