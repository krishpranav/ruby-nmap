module Nmap

    class Status < Struct.new(:state, :reason, :reason_ttl)

        def to_s
            self.state.to_s
        end
    end
end
