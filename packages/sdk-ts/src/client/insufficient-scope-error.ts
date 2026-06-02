// 403 insufficient-scope — the API key authenticated but does not grant the
// scope required for the endpoint.
//
// Wire-format extension members:
//   { "required": ["poe:create"], "granted": ["poe:read", "account:read"] }
//
// Both arrays are surfaced verbatim on the typed error. `requiredScope` is a
// convenience for the common single-scope case (the server emits a one-element
// `required` array today).

import { Cip309HttpError, type Cip309HttpErrorInit } from './http-error';

function readScopeArray(value: unknown): ReadonlyArray<string> {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string');
}

export class InsufficientScopeError extends Cip309HttpError {
  public readonly requiredScopes: ReadonlyArray<string>;
  public readonly grantedScopes: ReadonlyArray<string>;

  constructor(init: Cip309HttpErrorInit) {
    super(init);
    this.name = 'InsufficientScopeError';
    this.requiredScopes = readScopeArray(this.extensions['required']);
    this.grantedScopes = readScopeArray(this.extensions['granted']);
  }

  /** Convenience for the single-scope case; first entry of `requiredScopes`. */
  get requiredScope(): string | undefined {
    return this.requiredScopes[0];
  }
}
