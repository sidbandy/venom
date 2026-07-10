export { assessPackage, scanMalicious, checkCandidate } from './assess';
export type {
  BouncerVerdict,
  PackageAssessment,
  AssessOptions,
  MaliciousScanResult,
  ScanMaliciousOptions,
} from './assess';
export { detectTyposquat } from './typosquat';
export type { TyposquatResult } from './typosquat';
export { detectHomoglyphs } from './homoglyph';
export type { HomoglyphResult } from './homoglyph';
export { assessMaintainerRisk } from './maintainer-risk';
export type { MaintainerRiskSignal } from './maintainer-risk';
export { inspectInstallScripts, hasInstallLifecycle, INSTALL_LIFECYCLE } from './install-scripts';
export { scanSource } from './ast-scan';
export type { AstSignal, AstSignalKind } from './ast-scan';
export { shannonEntropy, findHighEntropyTokens } from './entropy';
export { levenshtein } from './levenshtein';
export { popularNamesFor } from './popular-names';
