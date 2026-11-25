import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import browser from 'webextension-polyfill';
import { createBodyRenderer } from '../../src/entries/Content/bodyRender';

// AWS Console pages load the content script at document_start: a render can arrive before <body> exists.
let body: HTMLElement;
const dropBody = () => { body = document.body; document.documentElement.removeChild(body); };
const restoreBody = () => { document.documentElement.appendChild(body); };
const flush = () => new Promise(resolve => setTimeout(resolve, 0));
afterEach(() => { if (!document.body) restoreBody(); document.body.innerHTML = ''; vi.restoreAllMocks(); });

it('renders at once when the body exists', () => {
  const render = vi.fn();
  createBodyRenderer(document)(render);
  expect(render).toHaveBeenCalledTimes(1);
});

it('waits for the body and runs only the latest render once', async () => {
  dropBody();
  const first = vi.fn(), latest = vi.fn(), whenBody = createBodyRenderer(document);
  whenBody(first); whenBody(latest);
  await flush();
  expect(first).not.toHaveBeenCalled(); expect(latest).not.toHaveBeenCalled();
  restoreBody(); await flush();
  expect(first).not.toHaveBeenCalled(); expect(latest).toHaveBeenCalledTimes(1);
  whenBody(first);
  expect(first).toHaveBeenCalledTimes(1);
});

beforeEach(() => { vi.resetModules(); });

it('the content script shows a plugin panel that arrived before the body', async () => {
  vi.spyOn(document.head, 'appendChild').mockImplementation(node => node);
  vi.mocked(browser.runtime.sendMessage).mockResolvedValue(undefined);
  await import('../../src/entries/Content/index');
  const receive = vi.mocked(browser.runtime.onMessage.addListener).mock.calls.at(-1)![0] as
    (message: unknown, sender: { id: string }) => unknown;
  dropBody();
  const json = (text: string) => ({ type: 'div', options: {}, children: [text] });
  expect(() => receive({ type: 'RENDER_PLUGIN_UI', windowId: 4, json: json('Early panel') }, { id: 'test-extension-id' })).not.toThrow();
  receive({ type: 'RENDER_PLUGIN_UI', windowId: 4, json: json('Use your IAM-user session') }, { id: 'test-extension-id' });
  restoreBody(); await flush();
  expect(document.getElementById('tlsn-plugin-container')?.textContent).toBe('Use your IAM-user session');
});
