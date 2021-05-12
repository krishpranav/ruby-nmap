require 'nmap/os_class'
require 'nmap/os_match'

module Nmap

  class OS

    include Enumerable


    def initialize(node)
      @node = node
    end


    def each_class
      return enum_for(__method__) unless block_given?

      @node.xpath("osmatch/osclass").each do |osclass|
        yield OSClass.new(osclass)
      end

      return self
    end


    def classes
      each_class.to_a
    end


    def each_match
      return enum_for(__method__) unless block_given?

      @node.xpath("osmatch").map do |osclass|
        os_match = OSMatch.new(
          osclass['name'],
          osclass['accuracy'].to_i
        )

        yield os_match
      end

      return self
    end


    def matches
      each_match.to_a
    end

 
    def ports_used
      @ports_used ||= @node.xpath("portused/@portid").map do |port|
        port.inner_text.to_i
      end
    end


    def fingerprint
      @fingerprint ||= if (fingerprint = @node.at_xpath("osfingerprint/@fingerprint"))
                         fingerprint.inner_text
                       end
    end


    def each(&block)
      each_match(&block)
    end

  end
end
