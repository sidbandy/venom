/** Shared options for SBOM generation. Explicit overrides make output reproducible. */
export interface SbomOptions {
  /** ISO 8601 timestamp to stamp into the document. Defaults to now. */
  timestamp?: string;
  /** Venom version recorded as the generating tool. */
  toolVersion?: string;
  /**
   * Stable document identifier (SPDX namespace suffix / CycloneDX serialNumber
   * UUID). Defaults to a random UUID; pass a fixed value for reproducible output.
   */
  documentId?: string;
}
