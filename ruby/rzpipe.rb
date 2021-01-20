#!/usr/bin/env ruby

# author pancake@nopcode.org

require 'open3'
require 'json'
require 'shellwords'

# RzPipe is an easy way to communicate with the rizin core through ruby
class RzPipe
  def initialize(file = nil)
    @file = file
    if file.nil?
      fd_in, fd_out = getfds
      @read = IO.new(fd_in, 'r')
      @write = IO.new(fd_out, 'w')
      @pid = -1
    else
      execute file
    end
  end

  def cmd(str)
    @write.print "#{str}\n"
    @write.flush
    @read.gets("\0")[0..-2]
  end

  def cmdj(str)
    json(cmd(str))
  end

  def quit
    cmd('q!')
    @read.close
    @write.close
    return if @pid == -1

    ::Process.wait @pid
  end

  def json(str)
    return if str.nil?

    JSON.parse str.sub("\n", '').sub("\r", '')
  end

  private

  def getfds
    fd_in = ENV['RZPIPE_IN'].to_i
    fd_out = ENV['RZPIPE_OUT'].to_i
    if fd_in < 1 || fd_out < 1
      raise 'Cannot find RZPIPE_IN and RZPIPE_OUT environment variables'
    end

    [fd_in, fd_out]
  end

  def execute(file)
    exec = "rizin -q0 #{Shellwords.shellescape file} 2>/dev/null"
    write, read, wait_thr = Open3.popen2(exec)
    @read = read
    @write = write
    @pid = wait_thr.pid
    @read.gets("\0")
  end
end
