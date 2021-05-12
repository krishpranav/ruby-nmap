require 'nmap/scanner'
require 'nmap/scan_task'
require 'nmap/scan'
require 'nmap/host'
require 'nmap/run_stat'
require 'nmap/prescript'
require 'nmap/postscript'

require 'nokogiri'

module Nmap

  class XML

    include Enumerable

    # Path of the Nmap XML scan file
    attr_reader :path


    def initialize(document)
      case document
      when Nokogiri::XML::Document
        @doc = document
      when IO, StringIO
        @doc = Nokogiri::XML(document)
      else
        @path = File.expand_path(document)
        @doc  = File.open(@path) { |file| Nokogiri::XML(file) }
      end

      yield self if block_given?
    end


    def self.parse(text,&block)
      new(Nokogiri::XML(text),&block)
    end


    def self.load(text,&block)
      parse(text,&block)
    end


    def self.open(path,&block)
      new(path,&block)
    end


    def scanner
      @scanner ||= Scanner.new(
        @doc.root['scanner'],
        @doc.root['version'],
        @doc.root['args'],
        Time.at(@doc.root['start'].to_i)
      )
    end


    def version
      @version ||= @doc.root['xmloutputversion']
    end

    def scan_info
      @doc.xpath('/nmaprun/scaninfo').map do |scaninfo|
        Scan.new(
          scaninfo['type'].to_sym,
          scaninfo['protocol'].to_sym,
          scaninfo['services'].split(',').map { |ports|
            if ports.include?('-')
              Range.new(*(ports.split('-',2)))
            else
              ports.to_i
            end
          }
        )
      end
    end


    def each_run_stat
      return enum_for(__method__) unless block_given?

      @doc.xpath('/nmaprun/runstats/finished').each do |run_stat|
        yield RunStat.new(
          Time.at(run_stat['time'].to_i),
          run_stat['elapsed'],
          run_stat['summary'],
          run_stat['exit']
        )
      end

      return self
    end


    def run_stats
      each_run_stat.to_a
    end

    def verbose
      @verbose ||= @doc.at('verbose/@level').inner_text.to_i
    end

    def debugging
      @debugging ||= @doc.at('debugging/@level').inner_text.to_i
    end


    def each_task
      return enum_for(__method__) unless block_given?

      @doc.xpath('/nmaprun/taskbegin').each do |task_begin|
        task_end = task_begin.xpath('following-sibling::taskend').first

        yield ScanTask.new(
          task_begin['task'],
          Time.at(task_begin['time'].to_i),
          Time.at(task_end['time'].to_i),
          task_end['extrainfo']
        )
      end

      return self
    end


    def tasks
      each_task.to_a
    end


    def task(name)
      each_task.find { |scan_task| scan_task.name == name }
    end


    def prescript
      @prescript ||= if (prescript = @doc.at('prescript'))
                       Prescript.new(prescript)
                     end
    end

    alias prescripts prescript


    def postscript
      @postscript ||= if (postscript = @doc.at('postscript'))
                        Postscript.new(postscript)
                      end
    end

    alias postscripts postscript

    def each_host
      return enum_for(__method__) unless block_given?

      @doc.xpath('/nmaprun/host').each do |host|
        yield Host.new(host)
      end

      return self
    end


    def hosts
      each_host.to_a
    end


    def host
      each_host.first
    end

    def each_down_host
      return enum_for(__method__) unless block_given?

      @doc.xpath("/nmaprun/host[status[@state='down']]").each do |host|
        yield Host.new(host)
      end

      return self
    end


    def down_hosts
      each_down_host.to_a
    end

    def down_host
      each_down_host.first
    end


    def each_up_host
      return enum_for(__method__) unless block_given?

      @doc.xpath("/nmaprun/host[status[@state='up']]").each do |host|
        yield Host.new(host)
      end

      return self
    end


    def up_hosts
      each_up_host.to_a
    end


    def up_host
      each_up_host.first
    end

 
    def each(&block)
      each_up_host(&block)
    end


    def to_s
      @path.to_s
    end


    def inspect
      "#<#{self.class}: #{self}>"
    end

  end
end
