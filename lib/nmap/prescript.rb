require 'nmap/scripts'


module Nmap

    class Prescript

        include Scripts

        def initialize(node)
            @node = node

        end
    end
end
