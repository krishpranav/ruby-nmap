module Nmap

    class Scan < Struct.new(:type, :protocol, :services)

        def initialize(type, protocol, services=[])
            super(type, protocol, services)
        end


        def to_s
            "#{self.protocol} #{self.type}"
        end 
    end
end

