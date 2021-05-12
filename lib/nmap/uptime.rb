module Nmap

    class Uptime < Struct.new(:seconds, :last_boot)

        def to_s
            "uptime: #{self.seconds} (#{self.last_boot})"
        end
    end
end