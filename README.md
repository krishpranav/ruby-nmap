# ruby-nmap
A simple nmap made in ruby 

[![forthebadge](https://forthebadge.com/images/badges/made-with-ruby.svg)](https://forthebadge.com)

# Installation
```
git clone https://github.com/krishpranav/ruby-nmap
cd ruby-nmap
gem install
gem install ruby-nmap
ruby-nmap
```

## Examples

Run Nmap from Ruby:

```ruby
require 'nmap/program'

Nmap::Program.scan do |nmap|
  nmap.syn_scan = true
  nmap.service_scan = true
  nmap.os_fingerprint = true
  nmap.xml = 'scan.xml'
  nmap.verbose = true

  nmap.ports = [20,21,22,23,25,80,110,443,512,522,8080,1080]
  nmap.targets = '192.168.1.*'
end
```

Run `sudo nmap` from Ruby:

```ruby
require 'nmap/program'

Nmap::Program.sudo_scan do |nmap|
  nmap.syn_scan = true
  # ...
end
```

Parse Nmap XML scan files:

```ruby
require 'nmap/xml'

Nmap::XML.new('scan.xml') do |xml|
  xml.each_host do |host|
    puts "[#{host.ip}]"

    host.each_port do |port|
      puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"
    end
  end
end
```

Print NSE script output from an XML scan file:

```ruby
require 'nmap/xml'

Nmap::XML.new('nse.xml') do |xml|
  xml.each_host do |host|
    puts "[#{host.ip}]"

    host.scripts.each do |name,output|
      output.each_line { |line| puts "  #{line}" }
    end

    host.each_port do |port|
      puts "  [#{port.number}/#{port.protocol}]"

      port.scripts.each do |name,output|
        puts " [#{name}]"

        output.each_line { |line| puts "#{line}" }
      end
    end
  end
end
```

## Requirements

* [ruby] >= 2.0.0
* [nmap] >= 5.00
* [nokogiri] ~> 1.3
* [rprogram] ~> 0.3
