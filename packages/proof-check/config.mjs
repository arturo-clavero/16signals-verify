// Check configuration: which provider descriptors to load, which keys to trust, which registries an app offers.

/**
 * A config file, with paths relative to the file itself:
 * `{ "providers": ["./my-provider/descriptor.mjs"], "keys": "./keys.json", "registries": [{ "type": "...", ... }] }`.
 * Each provider module default-exports a ProviderDescriptor. `keys` is a path or the TrustedKeys object itself.
 * `registries` are app-specific entries (for example `{ "type": "bnb", "module": "...", "network": "bsc-testnet" }`);
 * only their `module` path is resolved here, the app turns them into Registry objects.
 * @typedef {{ providers: (string | object)[], keys: string | object, registries?: { module?: string }[] }} CheckConfig
 */

/** Resolves a config's paths against `base` (the config's URL): imports providers and reads the keys. */
export async function resolveConfig(config, base, { readJson }) {
  const url = path => new URL(path, base);
  return {
    providers: await Promise.all((config?.providers ?? []).map(async entry =>
      typeof entry === 'string' ? (await import(url(entry).href)).default : entry)),
    keys: typeof config?.keys === 'string' ? await readJson(url(config.keys)) : config?.keys ?? { keys: [] },
    registries: (config?.registries ?? []).map(entry =>
      typeof entry?.module === 'string' ? { ...entry, module: url(entry.module).href } : entry),
  };
}

/** Reads a config file and resolves it. `readJson(url)` reads JSON in the host environment (fetch, fs). */
export async function loadConfig(url, { readJson }) {
  return resolveConfig(await readJson(new URL(url)), url, { readJson });
}
