// Issue construction and the normative issue ordering.
//
// The report's issue list merges the structural validator's output with every
// verifier-layer code the run raises. The combined list is sorted by the same
// rule the validator uses internally, so two implementations replaying the
// same run emit byte-identical issue order:
//
//   * paths compare segment-wise from the record root — two integer segments
//     numerically, two text segments by the bytewise order of their UTF-8
//     encodings, integer before text where the kinds differ, and a path that
//     is a strict prefix of another orders before it;
//   * issues carrying an identical path tie-break by the position of their
//     `code` in the error-code registry.
//
// Run-level verifier codes (TX_NOT_FOUND, PROVIDER_UNAVAILABLE, …) carry an
// empty path and therefore sort ahead of every record-located issue.

import {
  SEVERITY,
  errorCodeRegistryIndex,
  type ErrorCode,
  type Severity,
  type ValidationIssue,
} from '@cardanowall/poe-standard';

const UTF8 = new TextEncoder();

export type IssuePath = ReadonlyArray<string | number>;

// Build one issue with the registry's default severity for the code; pass
// `severity` to apply a context-promoted reading (dual-severity codes only —
// no code may ever be softened below its registry severity).
export function issueOf(
  code: ErrorCode,
  path: IssuePath,
  message: string,
  severity?: Severity,
): ValidationIssue {
  return { code, path, message, severity: severity ?? SEVERITY[code] };
}

function compareSegments(a: string | number, b: string | number): number {
  const aIsNumber = typeof a === 'number';
  const bIsNumber = typeof b === 'number';
  if (aIsNumber && bIsNumber) return (a as number) - (b as number);
  // Integer segments order before text segments where the kinds differ.
  if (aIsNumber !== bIsNumber) return aIsNumber ? -1 : 1;
  const aBytes = UTF8.encode(a as string);
  const bBytes = UTF8.encode(b as string);
  const n = Math.min(aBytes.length, bBytes.length);
  for (let i = 0; i < n; i++) {
    const d = aBytes[i]! - bBytes[i]!;
    if (d !== 0) return d;
  }
  return aBytes.length - bBytes.length;
}

export function compareIssuePaths(a: IssuePath, b: IssuePath): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = compareSegments(a[i]!, b[i]!);
    if (d !== 0) return d;
  }
  // A strict prefix orders before its extension.
  return a.length - b.length;
}

export function sortIssues(issues: ReadonlyArray<ValidationIssue>): ValidationIssue[] {
  return issues
    .slice()
    .sort(
      (a, b) =>
        compareIssuePaths(a.path, b.path) ||
        errorCodeRegistryIndex(a.code) - errorCodeRegistryIndex(b.code),
    );
}

// A mutable per-run sink the pipeline steps append to; the report assembly
// sorts once at emission.
export class IssueSink {
  private readonly issues: ValidationIssue[] = [];

  push(issue: ValidationIssue): void {
    this.issues.push(issue);
  }

  add(code: ErrorCode, path: IssuePath, message: string, severity?: Severity): void {
    this.issues.push(issueOf(code, path, message, severity));
  }

  // Idempotent add: a no-op when the sink already holds an issue with the
  // same code, path, and effective severity. Used where two pipeline layers
  // can legitimately conclude the same fact about the same location (e.g.
  // the structural validator and the signature pass both finding a signature
  // entry unsupported) and the report must carry it exactly once.
  addOnce(code: ErrorCode, path: IssuePath, message: string, severity?: Severity): void {
    const issue = issueOf(code, path, message, severity);
    const duplicate = this.issues.some(
      (existing) =>
        existing.code === issue.code &&
        existing.severity === issue.severity &&
        compareIssuePaths(existing.path, issue.path) === 0,
    );
    if (!duplicate) this.issues.push(issue);
  }

  pushAll(issues: ReadonlyArray<ValidationIssue>): void {
    this.issues.push(...issues);
  }

  has(code: ErrorCode): boolean {
    return this.issues.some((i) => i.code === code);
  }

  sorted(): ValidationIssue[] {
    return sortIssues(this.issues);
  }
}
