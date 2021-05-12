# requires
require 'nmap/cpe'

module Nmap

    class OSClass

        include CPE

        def initialize(node)
            @node = node
        end

        def type
            @type ||= if @node['type']
                @node['type'].to_sym
            end
        end

        def vendor
            @vendor ||= @node.get_attribute('vendor')
        end

        def family
            @family ||= @node.get_attribute('osfamily').to_sym
        end

        def gen
            @gen ||= if @node['osgen']
                @node['osgen'].to_sym
            end
        end


        def accuracy
            @accuracy ||= @node.get_attribute('accuracy').to_i
        end

        def to_s
            "#{self.type} #{self.vendor} (#{self.accuracy}%)"
        end
    end
end


