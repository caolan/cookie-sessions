#!/usr/local/bin/node

var nodeunit = require('./deps/nodeunit');

try {
    var testrunner = nodeunit.reporters.default;
}
catch(e) {
    var sys = require('sys');
    sys.puts("Cannot find nodeunit module.");
    sys.puts("You can download submodules for this project by doing:");
    sys.puts("");
    sys.puts("    git submodule init");
    sys.puts("    git submodule update");
    sys.puts("");
    process.exit();
}

process.chdir(__dirname);
testrunner.run(['test']);
