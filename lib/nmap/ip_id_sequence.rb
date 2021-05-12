require 'nmap/sequence'

module Nmap
    class IpIdSequence < Sequence
  
      def to_s
        "description=#{description.inspect} values=#{values.inspect}"
      end
  
    end
  end