require 'rubygems'
require 'pcap'
#require 'ruby-pcap'
#export RUBYLIB=/var/lib/gems/2.1.0/gems/ruby-pcap-0.7.9/lib/pcap/
#require 'pcaplet'
require '/var/lib/gems/2.1.0/gems/ruby-pcap-0.7.9/lib/pcap/pcaplet.rb'
require 'timeout'
require './Debugger.rb'
require './Csv_writer.rb'
require 'base64'
#sudo RUBYLIB=/var/lib/gems/2.1.0/gems/ruby-pcap-0.7.9/lib/pcap/ ruby2.1 Sniffer.rb 


class Sniffer

  
  # Hash
  #  { 'PORT'=>[{SRC_IP=> , DST_IP=> DATA=>}..............................] } 
  #     }
  # 
  #
  #  
@pkt_array
@collected_data
@timeout
@number_packtes_to_capture 
#initializa o objecto
# tem como parametro opcional o numero de pacotes que captura e o tempo de captura
#
def initialize(np=50,t=20)
  @collected_data = Hash.new  
  Debugger.set_level(1)
  @number_packtes_to_capture = np
  @timeout=t
  Debugger.debug("\nSetting timeout #{@timeout} and packet capture number: #{@number_packtes_to_capture}",1)
  
  @pkt_array = Array.new
end
 
#
# comeca a captura
# A captura esta limitada ao protocolo tcp 
# coloca toda a estrutura captura numa hastable para posteriormente ser escrita em ficheiro por a class Csv_Writer
def run


# export de RUBYLIB=/var/lib/gems/2.1.0/gems/ruby-pcap-0.7.9/lib/pcap/
# -c sintaxe tcpdump captura X pacotes
httpdump = Pcaplet.new("-s 1500 -c #{@number_packtes_to_capture}") # para ver como passar parametros para dentro

tcp_filter= Pcap::Filter.new('tcp ',httpdump.capture)
#TCP_FILTER = Pcap::Filter.new('tcp ',httpdump.capture)
 
#HTTP_REQUEST  = Pcap::Filter.new('tcp and dst port 80', httpdump.capture)
#HTTP_RESPONSE = Pcap::Filter.new('tcp and src port 80', httpdump.capture)

#httpdump.add_filter(TCP_FILTER)

#httpdump.add_filter(TCP_FILTER | HTTP_REQUEST | HTTP_RESPONSE)

httpdump.add_filter(tcp_filter)



begin 
      Timeout.timeout(@timeout) do
      httpdump.each_packet {|pkt|
      data = pkt.tcp_data
      case pkt
      when tcp_filter
       printf "#{pkt.src.to_s}:#{pkt.sport} <> #{pkt.dst.to_s}:#{pkt.dport} : \n" #if pkt.dport.to_i <= 1024# explorar aqui
       if pkt.dport.to_i # <=1024  
          begin
            if data == nil
              data=''
            end 

            @pkt_array << "#{pkt.src.to_s};#{pkt.sport};#{pkt.dst.to_s};#{pkt.dport};#{Base64.encode64(data)}\n"
            #@collected_data.fetch(pkt.dport.to_i)<<{'src_ip'=>"#{pkt.src.to_s}", 'dst_ip'=>"#{pkt.dst.to_s}", 'data'=>"#{Base64.encode64(data)}"}
            rescue KeyError
              if data == nil
                data=''
              end
            @collected_data.store(pkt.dport.to_i,[{'src_ip'=>"#{pkt.src.to_s}", 'dst_ip'=>"#{pkt.dst.to_s}", 'data'=>"#{Base64.encode64(data)}"}])             
          end
       end
# p data       
#      when HTTP_REQUEST
#        if data and data =~ /^GET\s+(\S+)/
#        path = $1
#        host = pkt.dst.to_s
#        host << ":#{pkt.dst_port}" if pkt.dport != 80
#        s = "#{pkt.src}:#{pkt.sport} > GET http://#{host}#{path}"
#        end
#     when HTTP_RESPONSE
#      if data and data =~ /^(HTTP\/.*)$/
#      status = $1
#      s = "#{pkt.dst}:#{pkt.dport} < #{status}"
#      
#    end
  end
#  puts s if s
}
end
  rescue Timeout::Error
   printf  "Sniffer ended\n"
ensure
  # p @collected_data
#Debugger.debug("expirou o tempo para analise",3)      
      
end     
end

def pcap_hash_format
  return @pkt_array
  return  @collected_data
end

  
def pcap_array_format
    return @pkt_array
end

#fim calss sniffer
end
#
#_test_user = "pedro"
#
#csv = Csv_writer.new(_test_user)
#
#s = Sniffer.new
#s.run
#p s.pcap_array_format
#
#csv.pcap_writer_array(s.pcap_array_format)




