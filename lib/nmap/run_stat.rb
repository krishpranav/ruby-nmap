module Nmap

    class RunStat < Struct.new(:end_time, :elapsed, :summary, :exit_status)

        def to_s
            "#{self.end_time} #{self.elapsed} #{self.exit_status}"
        end
    end
end
