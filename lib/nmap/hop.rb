module Nmap

    class Hop < Struct.new(:addr, :host, :ttl, :rtt)

        def to_s
            self.addr.to_s
        end
    end
end
