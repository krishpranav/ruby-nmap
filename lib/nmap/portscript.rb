require 'nmap/scripts'

module Nmap 

    class Postscript

        include Scripts

        def initialize(node)
            @node = node
        end
    end
end
