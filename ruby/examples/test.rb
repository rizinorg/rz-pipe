#!/usr/bin/env ruby

# author pancake@nopcode.org

require './rzpipe'

begin
  rzp = RzPipe.new
rescue Exception => e
  rzp = RzPipe.new '/bin/ls'
end
  puts rzp.cmd 'a'
  puts rzp.cmd 'pd 10 main'
  rzp.quit
