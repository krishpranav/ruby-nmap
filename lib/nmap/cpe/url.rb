module Nmap
    module CPE

      class URL < Struct.new(:part,:vendor,:product,:version,:update,:edition,
                             :language)
  

        PARTS = {
          '/a' => :application,
          '/h' => :hardware,
          '/o' => :os
        }
  

        def self.parse(url)
            scheme,
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language = url.split(':',8)
  
          unless scheme == 'cpe'
            raise(ArgumentError,"CPE URLs must begin with 'cpe:'")
          end
  
          vendor   = vendor.to_sym
          product  = product.to_sym
          language = language.to_sym if language
  
          return new(
            PARTS[part],
            vendor,
            product,
            version,
            update,
            edition,
            language
          )
        end

        def to_s
          'cpe:' + [
            PARTS.invert[part],
            vendor,
            product,
            version,
            update,
            edition,
            language
          ].compact.join(':')
        end
  
      end
    end
  end
  