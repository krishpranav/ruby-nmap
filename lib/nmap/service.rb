require 'nmap/cpe'

module Nmap

  class Service

    include CPE


    def initialize(node)
      @node = node
    end


    def name
      @name ||= @node.get_attribute('name')
    end


    def ssl?
      (@ssl ||= @node['tunnel']) == 'ssl'
    end


    def protocol
      @protocol ||= @node['proto']
    end


    def product
      @product ||= @node.get_attribute('product')
    end


    def version
      @version ||= @node.get_attribute('version')
    end


    def extra_info
      @extra_info ||= @node['extrainfo']
    end

    def hostname
      @hostname ||= @node.get_attribute('hostname')
    end


    def os_type
      @os_type ||= @node['ostype']
    end

    
    def device_type
      @device_type ||= @node['devicetype']
    end


    def fingerprint_method
      @fingerprint_method ||= @node.get_attribute('method').to_sym
    end

    def fingerprint
      @fingerprint ||= @node.get_attribute('servicefp')
    end
      
    def confidence
      @confidence ||= @node.get_attribute('conf').to_i
    end


    def to_s
      if (product && version)
        "#{product} #{version}"
      else
        name
      end
    end

  end
end
