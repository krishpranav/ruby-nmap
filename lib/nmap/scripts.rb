module Nmap
    module Scripts

      def scripts
        unless @scripts
          @scripts = {}
  
          @node.xpath('script').each do |script|
            @scripts[script['id']] = script['output']
          end
        end
  
        return @scripts
      end
  
      def script_data
        unless @script_data
          @script_data = {}
  
          traverse = lambda do |node|
            case node.name
            when 'script', 'table'
              unless node.xpath('*[@key]').empty?
                hash = {}
  
                node.elements.each do |element|
                  hash[element['key']] = traverse.call(element)
                end
  
                hash
              else
                array = []
  
                node.elements.each do |element|
                  array << traverse.call(element)
                end
  
                array
              end
            when 'elem'
              node.inner_text
            else
              raise(NotImplementedError,"unrecognized XML NSE element: #{node}")
            end
          end
  
          @node.xpath('script').each do |script|
            @script_data[script['id']] = traverse.call(script)
          end
        end
  
        return @script_data
      end
  
    end
  end