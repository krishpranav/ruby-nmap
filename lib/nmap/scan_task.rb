module Nmap

    class ScanTask < Struct.new(:name, :start_time, :end_time, :extrainfo)

        def initialize(name, start_time, end_time, extrainfo=nil)
            super
        end

        alias extra_info extrainfo


        def duration
            (self.end_time - self.start_time)
        end
        
        def to_s
            "#{self.start_time}: #{self.name} (#{self.extrainfo})"
        end
    end
end


