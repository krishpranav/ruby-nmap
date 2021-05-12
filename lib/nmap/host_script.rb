require 'nmap/scripts'

module Nmap

    class HostScript

        include Scripts

        def initialize(node)
            @node = node
        end
    end
end
