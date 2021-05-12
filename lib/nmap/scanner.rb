module Nmap

    class Scanner < Struct.new(:name, :version, :arguments, :start_time)

        def to_s
            "#{self.name} #{self.arguments}"
        end
    end
end
