# ip or mac address vendor name

module Nmap

    class Address < Struct.new(:type, :addr, :vendor)

        def initialize(type, addr, vendor=nil)
            super(type, addr, vendor)
        end

        def to_s
            self.addr.to_s
        end
    end
end
