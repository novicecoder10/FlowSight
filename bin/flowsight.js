#!/usr/bin/env node
// Entry point for the published package. The server binds and starts on require,
// reading data/ and cpp-sniffer/ relative to the working directory, so run it from
// the directory you want FlowSight to keep its database in.
require('../dist/index.js');
