// Types of the plugin sandbox capabilities the private-proof plugins use (a subset of packages/plugin-sdk's globals,
// without its `declare global` block). Each plugin declares the capabilities it uses as module-scoped consts.

export type DomOptions = { style?: Record<string, string>; [key: string]: unknown };
export type DomJson = { type: string; options: DomOptions; children: DomJson[] } | string;

export type DivFunction = {
  (options?: DomOptions, children?: DomJson[]): DomJson;
  (children: DomJson[]): DomJson;
};
export type OpenWindowFunction = (url: string, options?: { width?: number; height?: number; showOverlay?: boolean })
  => Promise<{ windowId: number; uuid: string; tabId: number }>;
export type UseEffectFunction = (callback: () => void, deps: unknown[]) => void;
export type InterceptedRequestHeader = {
  id: string; method: string; url: string; timestamp: number; type: string;
  requestHeaders: Array<{ name: string; value?: string }>; tabId: number;
};
export type UseHeadersFunction = (filter: (headers: InterceptedRequestHeader[]) => InterceptedRequestHeader[])
  => InterceptedRequestHeader[];
export type UseStateFunction = <T>(key: string, defaultValue: T) => T;
export type SetStateFunction = <T>(key: string, value: T) => void;
export type DoneFunction = (result?: unknown) => void;

/** One HTTP request to notarize, as the extension's private-proof collector hands it to the plugin. */
export type ProveRequest = { url: string; method: string; headers: Record<string, string | undefined>; body?: string };
export type ProveOptions = {
  verifierUrl: string; proxyUrl: string; maxRecvData?: number; maxSentData?: number; handlers: unknown[];
  /** Sent to the verifier with the session; its webhook receives it. */
  sessionData: Record<string, string>;
};
export type ProveFunction = (request: ProveRequest, options: ProveOptions) => Promise<unknown>;
