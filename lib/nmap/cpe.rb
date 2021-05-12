require 'nmap/cpe/url'

module Nmap

  module CPE
    def each_cpe
      return enum_for(__method__) unless block_given?

      @node.xpath('cpe').each do |cpe|
        yield URL.parse(cpe.inner_text)
      end

      return self
    end

    def cpe
      each_cpe.to_a
    end
  end
end