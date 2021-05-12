require 'nmap/sequence'

module Nmap

  class TcpSequence < Sequence

 
    def index
      @index ||= if (index_string = @node['index'])
                   index_string.to_i
                 end
    end

    def difficulty
      @difficulty ||= @node['difficulty']
    end

    def to_s
      "index=#{index} difficulty=#{difficulty.inspect} values=#{values.inspect}"
    end

  end
end