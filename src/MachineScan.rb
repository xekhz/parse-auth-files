# -*- coding: utf-8 -*-
require 'celluloid'
require "resolv"
require './portscanner.rb'
require './Debugger.rb'

# Este programa recebe um URL ou endereco IPV4 e executa um portscan 
#
#Autor:: Pedro Ferreira - Nº14976
#

class MachineScan
  include Celluloid
 
  #metodo construtor
  #recebe endereço , porto de inicio e porto de fim
  def initialize(address,start_port,end_port)
  @start_port = start_port
  @end_port = end_port
  @ip_address = address
  @open_ports_list = Array.new
  Debugger.set_level(1)   
    if (@start_port >= @end_port) then
      tmp_port = @start_port
      @start_port = @end_port
      @end_port = tmp_port
    end 
  end
  
  
  #Verifica se é um endereço IPV4 valido e caso seja um URL resolve o endereço 
  def resolv_address
  address = @ip_address
    re = /(\d+)\.(\d+)\.(\d+)\.(\d+)/
    match = address.match re
    
    if match == nil then
      Debugger.debug("Trying to resolve #{address}\n",1);
      
      begin
        res = Resolv::DNS.new(nil)
        @ip_address= res.getaddress(address).to_s
        match = @ip_adress.to_s.match re
        Debugger.debug("Address resolved #{@ip_address}\n",1)
      rescue
        Debugger.debug("Could not resolve #{address}\n",1)
        Debugger.debug("defaulting to ip_address = 127.0.0.1\n",1)
        @ip_address = "127.0.0.1"
      end 
              
    else
      if !(match[1].to_i <= 255 && match[2].to_i<=255 && match[3].to_i<=255 && match[4].to_i<=255) then
          ############################################## provavelmente e um url
          # resolve dns
          else  
            @ip_address = match[0]
      end
   end
  
   
  end
  
  
  
  def strip_protocol
  end
  
  #executa a chama da portscanner
  #Lança thread a thread que analiza por default 100 portos por thread
  #
  #*segment_size - controlo indirecto de threads, ao mudar o valor da variavel controla-se o numero de threads que o programa lança
  def run
 
    resolv_address
  
    segment_size = 100
    until @start_port >= @end_port do
    sp = ScanPort.new @start_port, @start_port + segment_size, @ip_address
    sp.async.run
     if (sp.get_open_ports.size > 0) then
        Debugger.debug("open port: #{sp.get_open_ports}\n",2)
        @open_ports_list = @open_ports_list + sp.get_open_ports
      end  
    @start_port += segment_size
    # thread de segment_size em segment_size
    end
  end
  
  #obtem a informacao dos portos que estão abertos num determinado momento
  def get_report
    Debugger.debug("\nPorts Open\n",1)
    Debugger.debug("(.)(.)(.)(.)(.)(.)\n",1)
    Debugger.debug("\n#{@open_ports_list}\n\n",1)
  end
  
  
  
  private :resolv_address, :strip_protocol
  public :run, :get_report
    
  
end
#EXEMPLO DE UTILIZACAO
#M = MachineScan.new("192.168.0.251",1,10000)
#M.run
#M.get_report

#Socket.ip_address_list.map {|el| p el.ip_address}
