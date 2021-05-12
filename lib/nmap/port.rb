# requires
require 'nmap/service'
require 'nmap/scripts'

module Nmap
  class Port

    include Scripts


    def initialize(node)
      @node = node
    end

    def protocol
      @protocol ||= @node['protocol'].to_sym
    end


    def number
      @number ||= @node['portid'].to_i
    end


    def state
      @state ||= @node.at_xpath('state/@state').inner_text.to_sym
    end


    def reason
      @reason ||= @node.at_xpath('state/@reason').inner_text
    end


    def reason_ttl
      @reason ||= @node.at_xpath('state/@reason_ttl').inner_text.to_i
    end


    def service
      @service_info ||= if (service = @node.at_xpath('service'))
                          Service.new(service)
                        end
    end

    alias to_i number


    def to_s
      number.to_s
    end


    def inspect
      "#<#{self.class}: #{self}>"
    end

  end
end
