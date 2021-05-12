require 'nmap/sequence'

module Nmap
  #
  # Represents a TCP timestamp.
  #
  class TcpTsSequence < Sequence

    def to_s
      "description=#{description.inspect} values=#{values.inspect}"
    end

  end
end