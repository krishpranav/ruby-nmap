require 'nmap/hop'

module Nmap

  class Traceroute

    include Enumerable

    def initialize(node)
      @node = node
    end

    
    def port
      @port ||= if @node['port']
                  @node['port'].to_i
                end
    end


    def protocol
      @protocol ||= if @node['proto']
                      @node['proto'].to_sym
                    end
    end

    def each
      return enum_for(__method__) unless block_given?

      @node.xpath('hop').each do |hop|
        yield Hop.new(hop['ipaddr'],hop['host'],hop['ttl'],hop['rtt'])
      end

      return self
    end

  end
end
