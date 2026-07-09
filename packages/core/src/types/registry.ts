import type { PackageRef } from './ecosystem';

export interface MaintainerInfo {
  username?: string;
  email?: string;
}

/**
 * Package metadata fetched from a registry (npm registry API / PyPI JSON API),
 * feeding maintainer-risk scoring (Module 3) and dependency health cards
 * (Section 5). All fields optional — registries vary in what they expose.
 */
export interface RegistryMetadata {
  ref: PackageRef;
  maintainers: MaintainerInfo[];
  latestVersion?: string;
  /** ISO date this specific version was published. */
  publishedAt?: string;
  /** ISO date of the most recent publish of any version. */
  lastPublishAt?: string;
  weeklyDownloads?: number;
  license?: string;
  repositoryUrl?: string;
  homepage?: string;
  deprecated?: boolean;
  /** True if the package declares install lifecycle scripts (npm). */
  hasInstallScripts?: boolean;
  /** Lifecycle script name → command, when available (for install-script inspection). */
  installScripts?: Record<string, string>;
  allVersions?: string[];
}

/**
 * A package tarball that has been downloaded and safely extracted **without
 * executing any code** (SPEC.md §4 M3). The extractor guards against path
 * traversal, symlink escape, and decompression bombs. Callers must `dispose()`
 * to remove the temp directory.
 */
export interface FetchedTarball {
  ref: PackageRef;
  /** Absolute path to the extracted contents in a temp directory. */
  extractedPath: string;
  /** Total uncompressed size, for bomb-detection reporting. */
  totalBytes: number;
  fileCount: number;
  dispose(): Promise<void>;
}
