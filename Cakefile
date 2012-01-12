# Based on https://github.com/twilson63/express-coffee/blob/master/Cakefile

fs            = require 'fs'
{print}       = require 'sys'
{spawn, exec} = require 'child_process'

build = (callback) ->
  options = ['-c', '-o', 'lib', 'src']
  coffee = spawn 'coffee', options
  coffee.stdout.on 'data', (data) -> print data.toString()
  coffee.stderr.on 'data', (data) -> print data.toString()
  coffee.on 'exit', (status) -> callback?() if status is 0

task 'build', 'Compile CoffeeScript source files', ->
  build()

