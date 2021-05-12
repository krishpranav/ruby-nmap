# requires
require 'nmap/status'
require 'nmap/address'
require 'nmap/hostname'
require 'nmap/os'
require 'nmap/port'
require 'nmap/ip_id_sequence'
require 'nmap/tcp_sequence'
require 'nmap/tcp_ts_sequence'
require 'nmap/uptime'
require 'nmap/traceroute'
require 'nmap/host_script'

require 'nokogiri'
require 'time'

module Nmap

  class Host

    include Enumerable


    def initialize(node)
      @node = node
    end

    
    def start_time
      @start_time ||= Time.at(@node['starttime'].to_i)
    end


    def end_time
      @end_time ||= Time.at(@node['endtime'].to_i)
    end

    def status
      unless @status
        status = @node.at_xpath('status')

        @status = Status.new(
          status['state'].to_sym,
          status['reason'],
          status['reason_ttl'].to_i
        )
      end

      return @status
    end


    def each_address
      return enum_for(__method__) unless block_given?

      @node.xpath("address[@addr]").each do |addr|
        address = Address.new(
          addr['addrtype'].to_sym,
          addr['addr'],
          addr['vendor']
        )

        yield address
      end

      return self
    end

    def addresses
      each_address.to_a
    end


    def mac
      @mac ||= if (addr = @node.at_xpath("address[@addrtype='mac']"))
                 addr['addr']
               end
    end

    def vendor
      @vendor ||= if (vendor = @node.at_xpath("address/@vendor"))
                 vendor.inner_text
               end
    end


    def ipv4
      @ipv4 ||= if (addr = @node.at_xpath("address[@addrtype='ipv4']"))
                  addr['addr']
                end
    end


    def ipv6
      @ipv6 ||= if (addr = @node.at_xpath("address[@addrtype='ipv6']"))
                  addr['addr']
                end
    end


    def ip
      ipv6 || ipv4
    end

    
    def address
      ip || mac
    end


    def each_hostname
      return enum_for(__method__) unless block_given?

      @node.xpath("hostnames/hostname[@name]").each do |host|
        yield Hostname.new(host['type'],host['name'])
      end

      return self
    end


    def hostnames
      each_hostname.to_a
    end


    def hostname
      each_hostname.first
    end


    def os
      @os ||= if (os = @node.at_xpath('os'))
                OS.new(os)
              end

      yield @os if (@os && block_given?)
      return @os
    end
      
    def uptime
      @uptime ||= if (uptime = @node.at_xpath('uptime'))
                    Uptime.new(
                      uptime['seconds'].to_i,
                      Time.parse(uptime['lastboot'])
                    )
                  end

      yield @uptime if (@uptime && block_given?)
      return @uptime
    end



    def tcp_sequence
      @tcp_sequence ||= if (seq = @node.at_xpath('tcpsequence'))
                          TcpSequence.new(seq)
                        end

      yield @tcp_sequence if (@tcp_sequence && block_given?)
      return @tcp_sequence
    end


    def tcpsequence(&block)
      warn "DEPRECATION: use #{self.class}#tcp_sequence instead"

      tcp_sequence(&block)
    end

    def ip_id_sequence
      @ip_id_sequence ||= if (seq = @node.at_xpath('ipidsequence'))
                            IpIdSequence.new(seq)
                          end

      yield @ip_id_sequence if (@ip_id_sequence && block_given?)
      return @ip_id_sequence
    end

    def ipidsequence(&block)
      warn "DEPRECATION: use #{self.class}#ip_id_sequence instead"

      ip_id_sequence(&block)
    end


    def tcp_ts_sequence
      @tcp_ts_sequence ||= if (seq = @node.at_xpath('tcptssequence'))
                             TcpTsSequence.new(seq)
                           end

      yield @tcp_ts_sequence if (@tcp_ts_sequence && block_given?)
      return @tcp_ts_sequence
    end


    def tcptssequence(&block)
      warn "DEPRECATION: use #{self.class}#tcp_ts_sequence instead"

      tcp_ts_sequence(&block)
    end

    def each_port
      return enum_for(__method__) unless block_given?

      @node.xpath("ports/port").each do |port|
        yield Port.new(port)
      end

      return self
    end

    def ports
      each_port.to_a
    end


    def each_open_port
      return enum_for(__method__) unless block_given?

      @node.xpath("ports/port[state/@state='open']").each do |port|
        yield Port.new(port)
      end

      return self
    end


    def open_ports
      each_open_port.to_a
    end

    
    def each_tcp_port
      return enum_for(__method__) unless block_given?

      @node.xpath("ports/port[@protocol='tcp']").each do |port|
        yield Port.new(port)
      end

      return self
    end


    def tcp_ports
      each_tcp_port.to_a
    end


    def each_udp_port
      return enum_for(__method__) unless block_given?

      @node.xpath("ports/port[@protocol='udp']").each do |port|
        yield Port.new(port)
      end

      return self
    end


    def udp_ports
      each_udp_port.to_a
    end

    def each(&block)
      each_open_port(&block)
    end

    def scripts
      if host_script
        host_script.scripts
      else
        {}
      end
    end


    def host_script
      @host_script ||= if (hostscript = @node.at_xpath('hostscript'))
                         HostScript.new(hostscript)
                       end
    end

    def traceroute
      @traceroute ||= if (trace = @node.at_xpath('trace'))
                        Traceroute.new(trace)
                      end

      yield @traceroute if (@traceroute && block_given?)
      return @traceroute
    end

    def to_s
      (hostname || address).to_s
    end

    def inspect
      "#<#{self.class}: #{self}>"
    end

  end
end
