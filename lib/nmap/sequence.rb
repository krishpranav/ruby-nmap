module Nmap

    class Sequence
  

      def initialize(node)
        @node = node
      end
  

      def description
        @description ||= @node['class']
      end
  

      def values
        @values ||= if @node['values']
                      @node['values'].split(',').map { |value| value.to_i(16) }
                    else
                      []
                    end
      end
  
    end
  end