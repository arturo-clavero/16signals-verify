// The checking side of the built-in providers, for @16signals-verify/proof-check.
import aws from './aws/descriptor.mjs';
import cloudflare from './cloudflare/descriptor.mjs';
import gcp from './gcp/descriptor.mjs';

export { aws, cloudflare, gcp };
/** All three descriptors, in the order verify/verify.config.json lists them. */
export default Object.freeze([gcp, aws, cloudflare]);
