export { detectUnusedDependencies } from './unused-deps';
export type { UnusedResult } from './unused-deps';
export { checkLicenses } from './licenses';
export type { LicenseResult, LicenseOptions } from './licenses';
export { checkSecretsHygiene } from './secrets-hygiene';
export type { HygieneResult } from './secrets-hygiene';
export { extractImports, packageNameOf, collectImportedPackages } from './imports';
export { computeReachablePackages } from './reachability';
