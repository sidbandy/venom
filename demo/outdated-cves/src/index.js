// Uses both dependencies so they aren't reported as unused — the point of this
// demo is the known CVEs in these old versions.
const _ = require('lodash');
const argv = require('minimist')(process.argv.slice(2));

console.log(_.chunk([1, 2, 3, 4], 2), argv);
