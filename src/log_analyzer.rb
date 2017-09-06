# -*- coding: utf-8 -*-
require './Debugger.rb'
require './Csv_writer.rb'
require 'geoip'
require 'worldize'

class Log_analyzer
  
@file;
@service_name_list
# Hash table que contem o servico e os hits por IP bem como a data da tentativa
# {"ssh"=>{"208.67.1.57"=>{"hits"=>1, "when"=>[#<MatchData "Apr 10 04:10:17" 1:"Apr 10 04:10:17">]}, "183.3.202.173"=>{"hits"=>18, "when"=>[.....]}}
@detections
@geoip
# country_code on runtime contem a iformacao do numero de hits por cada pais..(nao esta separado por servico) code3 com 3 letras por pais , code2 com 2 letras por pais
@country_code3
@country_code2
@fff
#
# Initializa o objecto e tem como requisito o nome do ficheiro a processar
#
#
def initialize(filename,debug_level)
  Debugger.set_level(debug_level)
  if File.exist?(filename) &&  File.readable?(filename)
  @filename = filename
  @file = File.open(filename,mode="r")
  services
  @detections = Hash.new
  @geoip = GeoIP.new('GeoIP.dat')
  @country_code3 = Hash.new
  @country_code2 = Hash.new
  @fff = Hash.new
  else
    Debugger.debug("Ficheiro nao existe: #{filename}",3)
    exit
 end
end

# A cada linha tenta faz o match para os servicos conhecidos.
def parse_log_file
  @file.each{ |linha|
    service_parser(linha)
  }
end
  # A cada linha tenta faz o match para os servicos conhecidos.    
def parse_firewall_file
    @file.each{ |linha|
      firewall_parser(linha)
    }
  end


# Verifica se o conteudo da linha pertence a algum dos servicos a analizar
# Ao identificar um servico tenta localizar o ip da tentativa de intrusao.
# a identificacao do ip é com base na expressao regular do output do servico
# 
def service_parser(l)
  @service_name_list.each{ |k,v|
    re = /#{k}/ 
    #p l
    #p re
    #p l.match re
    if l.match re #faz match na linha e no servico a analisar (k)
      v.each { |sre|
              if l.match sre
                ip_match  = l.match /(\d+\.\d+\.\d+\.\d+)/
                time_match = l.match /(\w{3}\s+\d{,2}\s+\d{2}:\d{2}:\d{2})/
                # martelada que ha sistemas que em vez de apresentarem a data como 01 apresentam como 1 so com 1 digito
                if ip_match
                   Debugger.debug("IP ENCONTRADO #{ip_match[1]}",4)
                   Debugger.debug(@geoip.country("#{ip_match[1]}"),4)
                   # verifica se o ip se encontra na lista de ocorrencais e incrementa 1
                begin
                  iphash = (@detections.fetch(k))
                  #iphash[ip_match[1]]=iphash.fetch(ip_match[1])+1
                  begin
                  tmp_ip_time_hash = iphash.fetch(ip_match[1])
                  tmp_ip_time_hash['hits']=tmp_ip_time_hash['hits']+1
                  tmp_ip_time_hash['when']=tmp_ip_time_hash['when']<< time_match 
               rescue KeyError
                  iphash.store(ip_match[1],{'hits'=>1 , 'when'=>[time_match]})
                end
                rescue KeyError
                  # so executa quando o ip ainda n existe no HASH
                  (@detections.fetch(k)).store(ip_match[1],{'hits'=>1 , 'when'=>[time_match]})
                end              
                
                begin
                  @country_code3.store(@geoip.country("#{ip_match[1]}").country_code3, @country_code3.fetch(@geoip.country("#{ip_match[1]}").country_code3) +1 )
                  @country_code2.store(@geoip.country("#{ip_match[1]}").country_code2, @country_code2.fetch(@geoip.country("#{ip_match[1]}").country_code2) +1 )

                rescue KeyError
                  @country_code3.store(@geoip.country("#{ip_match[1]}").country_code3,1)
                  @country_code2.store(@geoip.country("#{ip_match[1]}").country_code2,1)
               end                   
                end
              end
            }
    end
    
     }
end

# identico ao service parser
# porem como a estrutura do ficheiro é diferente o codigo de analise tambem o é
# 
#

def firewall_parser(l)
  
    
  @service_name_list.each{ |k,v|
     re = /#{k}/ 
     #p l
     #p re
     #p l.match re
     if l.match re #faz match na linha e no servico a analisar (k)
       v.each { |sre|
               if l.match sre
                 ip_match  = l.match /SRC=(\d+\.\d+\.\d+\.\d+)/
                 time_match = l.match /(\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2})/
                 dport = l.match /DPT=(\d+)/
                 dport = dport[1] if dport != nil
                 dport = "0" if dport == nil 
                 # p l
                 if ip_match
                  # p ip_match[1]
                    #Debugger.debug("IP ENCONTRADO #{ip_match[1]}\n",1)
                    #Debugger.debug(@geoip.country("#{ip_match[1]}"),4)
                    # verifica se o ip se encontra na lista de ocorrencais e incrementa 1
                 begin
                   #p"START #{@fff}"
                   port_hash = (@fff.fetch(k))                     
                   #p"port_hash #{port_hash}"
                     begin
                       begin 
                        ips_h = port_hash.fetch(dport)
                        
                        begin
                        tmp_ip_time_hash = ips_h.fetch(ip_match[1])
                         tmp_ip_time_hash['hits']=tmp_ip_time_hash['hits']+1
                         tmp_ip_time_hash['when']=tmp_ip_time_hash['when']<< time_match 
                         # ips_h.store("#{ip_match[1]}",{"when"=>[],"hits"=>1+ips_h.fetch("#{ip_match[1]}").fetch("hits")})
                        rescue
                        ips_h.store(ip_match[1],{"hits"=>1,"when"=>[time_match]})
                        end
                       rescue KeyError
                  #     p "134: A INSERIR #{ {dport=>{"#{ip_match[1]}"=>{"hits"=>1,"when"=>[time_match]}}} }"                        
                        port_hash.store(dport,{"#{ip_match[1]}"=>{"hits"=>1,"when"=>[time_match]}})
                       end                       
                     rescue KeyError 
                 #  p "138: A INSERIR #{ {k=>{"#{dport}"=>{"#{ip_match[1]}"=>{"hits"=>1,"when"=>[time_match]}}}} }"                     
                       @fff.store(k,{"#{dport}"=>{"#{ip_match[1]}"=>{"hits"=>1,"when"=>[time_match]}}})
                     end  
                 rescue KeyError
                   # so executa quando o ip ainda n existe no HASH
                   #p defined? @fff
                   #p "143: A INSERIR #{ {k=>{"#{dport}"=>{"#{ip_match[1]}"=>{"hits"=>1,"when"=>[time_match]}}}} }"
                   @fff.store(k,{"#{dport}"=>{"#{ip_match[1]}"=>{"hits"=>1,"when"=>[time_match]}}})
                   #p @fff
                 end              
                 
                end
               end
             #p "START"  
             #p @fff
             #p "####"
               }
     end
     
      }
  
end
# Hash com os servicos
# do ponto de vista para criar uma aplicacao mais dinamica é construido um Hash em que a chave é o servico e o conteudo
# é um array de expressoes regulares que detetem a intrusao ou tentativa de intrusao no servico
def services
  @service_name_list = Hash.new
  # @service_name_list = {
  #    "ssh"=>Array.new 
  #    }
  @detections = Hash.new
  # @detections = {
  #    "ssh" => Hash.new
  #  }    
end

# Caso se pretenda introduzir uma nova expressao regular para executar a procura de IPs mais correctamente
# é necessario indicar o servico. Servico e expressao regular que detecta IPs estao sempre na mesma linha
#  
# deteccao do ip
# <b>EXEMPLO</b>
# * l.insert_new_regexp_service("ssh",/ Failed password/) Servico a analisar ssh , expressao regular Failed password
# * l.insert_new_regexp_service("XPTO",/ TENTATIVA/) Servico a analisar XPTO , expressao regular TENTATIVA
# O ficheiro a analisar contem o servico ssh e na linha que contem o texto <i>Failed Password</i> encontramos o ip
# O ficheiro a analisar contem o servico XPTO e na linha que contem o texto <i>TENTATIVA</i> encontramos o ip
 
def insert_new_regexp_service(k,re)
  if ! @service_name_list.has_key?(k)
    @service_name_list.store(k,Array.new)
    @detections.store(k,Hash.new)
  end 
  @service_name_list[k]<<re
  Debugger.debug("Lista de nomes de servico",2)
  Debugger.debug("#{@service_name_list}",2)
end

# retorna a lista de servicos e os enderecos ipv4 com hits
# variavel de instancia @detections
def get_detections 
  Debugger.debug(@detections,3) 
  Debugger.debug(@country_code3,3)
  Debugger.debug(@country_code2,3) 
  return @detections
end

# retorna a lista de servicos e os enderecos ipv4 com hits
# variavel de instancia @fff
# foi criada esta funcao apra manter a coerencia logica.
# um tipo de ficheiro, um tipo de parser, e um tipo de funcoes de retorno

def get_firewall_detections 
  #Debugger.debug(@detections,3) 
  #Debugger.debug(@country_code3,3)
  #Debugger.debug(@country_code2,3) 
  return @fff
end

#
# retorna a variavel de instancia @country_code2 ( com 2 digitos q identificam o pais)
#

def get_country_list_code3  
return @country_code3
end

#
# retorna a variavel de instancia @country_code2 ( com 2 digitos q identificam o pais)
#
def get_country_list_code2  
return @country_code2
end

end 



#
# EXEMLPO DE UTILIZACAO
#
## START PROGRAM
##l = Log_analyzer.new("auth2.log")
##l.services()
##l.insert_new_regexp_service("ssh",/ Failed password/)
##l.insert_new_regexp_service("CRON",/ ATTEMPT/)
##l.parse_file()
#l.get_detections()

##_test_user="pedro"
##csv = Csv_writer.new(_test_user)
##csv.detections(l.get_detections)

 
# FIM DE PROGRAMA

#https://github.com/zverok/worldize
#ruby 2.1
#
#worldize = Worldize::Countries.new
#
#country_hits = l.get_country_list_code3
#country_colors = country_hits.clone
#
#country_colors.each{|k,v|  begin 
#                            my_color = ("#%06x" % (rand * 0xffffff))
#                            end while country_colors.value?(my_color)
#                            country_colors[k] = my_color
#                          }  
#
#Debugger.debug("Cores por cada pais",4)
#Debugger.debug(country_colors,4)
#
#
#
#
##desenho com cores sorteadas
#Worldize::Countries.new.
#  draw(
# country_colors
#  ).
#  write("report/images/#{_test_user}/country_colors.png") # nao esquecer colocar o user
#
##country_hits.delete("VNM")
##country_hits.delete("CHN")
##country_hits.delete("TUR")
#p country_hits
#if country_hits.size>1
##grandient baseado nos hits  
#worldize.
#  draw_gradient(
#    '#00FF4D', # gradient from this color
#    'FF0000', # ...to that color
#    country_hits  # ...according to value
#    ).
#write("report/images/#{_test_user}/country_gradient.png") # nao esquecer colocar user
#Debugger.debug("Imagens criadas em : report/images/country_colors.png\n",3) 
#Debugger.debug("Imagens criadas em : report/images/country_gradient.png\n",3) 
#end
#
## neste draw map é com o country code 
## require './ruby-data-map-master/data_map'
## countries = YAML.load_file('./ruby-data-map-master/lang/en/countries.yml')
## m = DataMap::WorldMap.new
## m.data = l.get_country_list_code2
## #m.title = 'Tentativas de acesso'
## #m.add_js
## m.identify_countries
## #m.make_ranges_log                                                                                                                                                                                                   
## m.make_ranges_linear
## m.make_colors
## m.map_values
## m.make_legend
## m.save_file('map.png', { :size => '1600x1200', :quality => 100})
## puts "Output at map.png"
## Use the country database:
##c = GeoIP.new('GeoIP.dat').country('www.nokia.com')
##p c
