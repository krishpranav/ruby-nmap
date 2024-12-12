module Nmap

    class Hostname < Struct.new(:type, :name)

        def user?
            self.type == 'user'
        end
        
        
        def ptr?
            self.type == 'PTR'
        end

        def to_s
            self.name.to_s
        end
    end
end
