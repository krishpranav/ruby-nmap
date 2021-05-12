require 'nmap/task'

require 'rprogram/program'

module Nmap

  class Program < RProgram::Program

    name_program 'nmap'


    def self.scan(options={},exec_options={},&block)
      find.scan(options,exec_options,&block)
    end

    def self.sudo_scan(options={},exec_options={},&block)
      find.sudo_scan(options,exec_options,&block)
    end

   
    def scan(options={},exec_options={},&block)
      run_task(Task.new(options,&block),exec_options)
    end


    def sudo_scan(options={},exec_options={},&block)
      sudo_task(Task.new(options,&block),exec_options)
    end

  end
end
