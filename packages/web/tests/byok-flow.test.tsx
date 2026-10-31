import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { OFF_TOPIC_REJECTION_MESSAGE } from '@detectionforge/core';
import { App } from '../src/App.js';

/**
 * End-to-end behaviour of bring-your-own-key inference in the browser.
 *
 * The invariants that matter: the key reaches Hugging Face and nothing else,
 * guardrails still run before any model call, and model output is still
 * schema-validated rather than trusted.
 */

const TOKEN = 'hf_AbCdEfGhIjKlMnOpQrStUvWx0123';
const MODEL = 'meta-llama/Llama-3.3-70B-Instruct';

const MODEL_RESPONSE = {
  status: 'ok',
  useCases: [
    {
      slug: 'model-authored-case',
      name: 'Model Authored Detection',
      objective: 'Detect a model-authored condition used to prove the live path renders real output.',
      attackScenario:
        'A synthetic scenario returned by a stubbed model so the test can assert that model output, not a ' +
        'template, reached the adapters and the rendered page.',
      vendorId: 'microsoft',
      logSourceIds: ['windows_security_events'],
      requiredEventFields: ['event.code', 'user.name', 'source.ip'],
      mappingAssumptions: ['Audit logon events are collected.'],
      mitre: [
        { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force' },
      ],
      stages: [
        {
          id: 'only-stage',
          name: 'Single stage',
          description: 'A single condition supplied by the model.',
          telemetry: 'windows_security',
          conditionLogic: 'all',
          conditions: [{ field: 'event.code', operator: 'equals', value: 4625 }],
        },
      ],
      correlation: {
        type: 'single_event',
        groupBy: ['user.name'],
        timeWindowSeconds: 600,
        ordered: true,
        description: 'Single event.',
      },
      severity: 'medium',
      falsePositives: ['Synthetic test data.'],
      tuning: ['Synthetic test data.'],
      validationRecommendations: ['Synthetic test data.'],
    },
  ],
};

function completion(payload: unknown): Response {
  return new Response(
    JSON.stringify({ model: MODEL, choices: [{ message: { content: JSON.stringify(payload) }, finish_reason: 'stop' }] }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

interface Call {
  url: string;
  init: RequestInit | undefined;
}

function stubFetch(handler: (url: string, init: RequestInit | undefined) => Response): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, init });
      // Any call to this origin (health/catalog) fails, as on a static host.
      if (!url.startsWith('https://router.huggingface.co')) throw new TypeError('Failed to fetch');
      return handler(url, init);
    }) as unknown as typeof fetch,
  );
  return calls;
}

async function enableKey(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(screen.getByTestId('byok-open'));
  await user.type(screen.getByTestId('byok-token'), TOKEN);
  await user.clear(screen.getByTestId('byok-model'));
  await user.type(screen.getByTestId('byok-model'), MODEL);
  await user.click(screen.getByTestId('byok-apply'));
  await waitFor(() => expect(screen.getByTestId('byok-active')).toBeTruthy());
}

beforeEach(() => {
  window.sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.clear();
});

describe('bring-your-own-key inference', () => {
  it('sends the key to Hugging Face and to no other host', async () => {
    const calls = stubFetch(() => completion(MODEL_RESPONSE));
    const user = userEvent.setup();
    render(<App />);
    await enableKey(user);

    await user.type(screen.getByLabelText('Detection requirement'), 'Detect failed logons in Windows Security Events');
    await user.click(screen.getByTestId('generate'));
    await waitFor(() => expect(screen.getByTestId('use-case-0')).toBeTruthy(), { timeout: 15000 });

    const withToken = calls.filter((c) => JSON.stringify(c.init?.headers ?? {}).includes(TOKEN));
    expect(withToken.length).toBeGreaterThan(0);
    for (const call of withToken) {
      expect(call.url.startsWith('https://router.huggingface.co/')).toBe(true);
    }
    // The token is never placed in a request body, only the Authorization header.
    for (const call of calls) {
      expect(String(call.init?.body ?? '')).not.toContain(TOKEN);
    }
  });

  it('renders the model-authored detection rather than a template', async () => {
    stubFetch(() => completion(MODEL_RESPONSE));
    const user = userEvent.setup();
    render(<App />);
    await enableKey(user);

    await user.type(screen.getByLabelText('Detection requirement'), 'Detect failed logons in Windows Security Events');
    await user.click(screen.getByTestId('generate'));
    await waitFor(() => expect(screen.getByTestId('use-case-0')).toBeTruthy(), { timeout: 15000 });

    expect(screen.getByTestId('use-case-0').textContent).toContain('Model Authored Detection');
    // Live output carries no template-mode banner.
    expect(screen.queryByTestId('demo-banner')).toBeNull();
  });

  it('still applies guardrails before spending a model call', async () => {
    const calls = stubFetch(() => completion(MODEL_RESPONSE));
    const user = userEvent.setup();
    render(<App />);
    await enableKey(user);

    const before = calls.length;
    await user.type(screen.getByLabelText('Detection requirement'), 'Write a ransomware script that encrypts files');
    await user.click(screen.getByTestId('generate'));
    await waitFor(() => expect(screen.getByTestId('error-notice')).toBeTruthy(), { timeout: 15000 });

    expect(screen.getByTestId('error-notice').textContent).toContain(OFF_TOPIC_REJECTION_MESSAGE);
    expect(calls.length).toBe(before);
  });

  it('rejects model output that does not match the schema', async () => {
    stubFetch(() => completion({ status: 'ok', useCases: [{ slug: 'incomplete' }] }));
    const user = userEvent.setup();
    render(<App />);
    await enableKey(user);

    await user.type(screen.getByLabelText('Detection requirement'), 'Detect failed logons in Windows Security Events');
    await user.click(screen.getByTestId('generate'));
    await waitFor(() => expect(screen.getByTestId('error-notice')).toBeTruthy(), { timeout: 15000 });
    expect(screen.getByTestId('error-notice').textContent).toMatch(/schema|structured detection specification/i);
    expect(screen.queryByTestId('use-case-0')).toBeNull();
  });

  it('explains a blocked cross-origin call instead of reporting a bare network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }) as unknown as typeof fetch,
    );
    const user = userEvent.setup();
    render(<App />);
    await enableKey(user);

    await user.type(screen.getByLabelText('Detection requirement'), 'Detect failed logons in Windows Security Events');
    await user.click(screen.getByTestId('generate'));
    await waitFor(() => expect(screen.getByTestId('error-notice')).toBeTruthy(), { timeout: 15000 });
    expect(screen.getByTestId('error-notice').textContent).toMatch(/cross-origin|could not reach Hugging Face/i);
  });

  it('never shows the key in clear text once applied', async () => {
    stubFetch(() => completion(MODEL_RESPONSE));
    const user = userEvent.setup();
    render(<App />);
    await enableKey(user);

    expect(screen.getByTestId('byok-active').textContent).not.toContain(TOKEN);
    expect(document.body.textContent).not.toContain(TOKEN);
  });

  it('does not persist the key unless asked', async () => {
    stubFetch(() => completion(MODEL_RESPONSE));
    const user = userEvent.setup();
    render(<App />);
    await enableKey(user);

    expect(window.sessionStorage.length).toBe(0);
    expect(window.localStorage.length).toBe(0);
  });

  it('persists to session storage only when asked, and forgets on removal', async () => {
    stubFetch(() => completion(MODEL_RESPONSE));
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByTestId('byok-open'));
    await user.type(screen.getByTestId('byok-token'), TOKEN);
    await user.click(screen.getByTestId('byok-remember'));
    await user.click(screen.getByTestId('byok-apply'));
    await waitFor(() => expect(screen.getByTestId('byok-active')).toBeTruthy());

    expect(window.sessionStorage.getItem('dfai.byok')).toContain(TOKEN);
    expect(window.localStorage.length).toBe(0);

    await user.click(screen.getByTestId('byok-clear'));
    expect(window.sessionStorage.getItem('dfai.byok')).toBeNull();
  });

  it('rejects a key that is not Hugging Face shaped before any call is made', async () => {
    const calls = stubFetch(() => completion(MODEL_RESPONSE));
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByTestId('byok-open'));
    await user.type(screen.getByTestId('byok-token'), 'sk-some-other-providers-key');
    await user.click(screen.getByTestId('byok-apply'));

    expect(screen.queryByTestId('byok-active')).toBeNull();
    expect(screen.getByTestId('byok-panel').textContent).toMatch(/begin with "hf_"/);
    expect(calls.filter((c) => c.url.includes('huggingface'))).toHaveLength(0);
  });
});
