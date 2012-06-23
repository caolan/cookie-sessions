#!/usr/local/bin/node

require.paths.push(__dirname);
require.paths.push(__dirname + '/deps');
require.paths.push(__dirname + '/lib');

try {
    var testrunner = require('nodeunit').testrunner;
}
catch(e) {
    var util = require('util');
    util.puts("Cannot find nodeunit module.");
    util.puts("You can download submodules for this project by doing:");
    util.puts("");
    util.puts("    git submodule init");
    util.puts("    git submodule update");
    util.puts("");
    process.exit();
}

process.chdir(__dirname);
testrunner.run(['test']);
