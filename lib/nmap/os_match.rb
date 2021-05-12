module Nmap

    class OSMatch < Struct.new(:name, :accuracy)

        def to_s
            "#{self.name} (#{self.accuracy}%)"
        end
    end
end
