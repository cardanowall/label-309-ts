// Raised synchronously from the Label309Client constructor when the config
// cannot be resolved into a usable gateway target. The single trigger: a
// missing or empty `baseUrl`. The client is gateway-agnostic and has no default
// deployment, so a full base URL — including the API version segment, e.g.
// `https://gateway.example.com/api/v1` — must always be supplied. The `apiKey`
// is an opaque bearer token and is never the cause of this error.

export class InvalidClientConfigError extends Error {
  public readonly code = 'INVALID_CLIENT_CONFIG' as const;
  constructor(message: string) {
    super(message);
    this.name = 'InvalidClientConfigError';
  }
}
