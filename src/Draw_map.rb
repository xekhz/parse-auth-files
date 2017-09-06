require 'geoip'
require 'worldize'
require './Debugger.rb'

# Classe responsavel por processar ficheiros CSV
# processa ficheiros CSV para criar os mapas
class Draw_map

@worldize  
@filename
@country_code3
@country_code2
@country_name
@country_colors
@information_by_date = Hash.new
# Verifica se o file que contem a informacao de um servico existe
# Recebe como input o ficheiro a processar
 
# initializa o objecto
# Recebe o ficheiro csv que deve ser processado
# Instancia o objecto que desenha o mapa 
# e instancia as variaveis que serao utilizadas no decorrer da construcao do mapa
def initialize(f)
  Debugger.set_level(1)
 if File.exist?(f) then
   @worldize = Worldize::Countries.new 
   @filename = f
#   @geoip = GeoIP.new('GeoIP.dat')
   @geoip = GeoIP.new('GeoLiteCity.dat')
   #contem o country e os hits
   @country_code3 = Hash.new()
   @country_code2 = Hash.new()
   @country_name = Hash.new
   @information_by_date = Hash.new
 else
   Debugger.debug("Ficheiro nao existe: #{f}",1)
   return
 end      
end

# processa linha a linha o ficheiro csv em questao
# atravez de expressao regular faz o match e retira a informacao pertinente e caso 
# seja possivel, com ip valido, consulta o GEOIP e retira a informacao da localizacao, nome do pais e os 3 e 2 digitos de identificacao do pais
# Durante o processo de analise constroi uma hash com a informacao do  country_hits, ou seja numero de tentativas do determinado pais e as horas da tentativa
def process_csv_file
  File.open(@filename).each{|line| 
    #Debugger.debug("A processar linha: #{line}",2)
    ip_match  = line.match /(\d+\.\d+\.\d+\.\d+)/
    if ip_match == nil
      ip_match=['127.0.0.1','127.0.0.1']
        p "Draw_map : 45 : ERRO em ip_match  = line.match /(\d+\.\d+\.\d+\.\d+)/ "
        next # erro no ip alerta e sai
    end
    date_match = line.match /(\d+\.\d+\.\d+\.\d+).;.(\w{3}\s+\d{,2})\s(\d{2}):\d{2}:\d{2}/ # Feb 24 10:27:46    
    _data =''
    _hour =''
    if date_match != nil 
    _data = date_match[2]
    _hour = date_match[3]
    else
      _data = 'UKNOWN'
      _hour = '--'
    end
    #p("#{@geoip.country(ip_match[1])}") 
    # p @geoip.country("#{ip_match[1]}")
  
    if @geoip.country("#{ip_match[1]}") == nil
      #
      # Para o caso de o IP nao se encontrar na base de dados temos de atribuir um valor de desconhecido
      #
      #
       begin
         
         @country_code3.store("A1",@country_code3.fetch("A1")+1)
         @country_code2.store("A1",@country_code2.fetch("A1")+1)
         @country_name.store("#{ip_match[1]}",@country_name.fetch("#{ip_match[1]}")+1)
         
       rescue
         
         @country_code3.store("A1",1)
         @country_code2.store("A1",1)
         @country_name.store("#{ip_match[1]}",1)
       end
      next
    end
   # @geoip.country("#{ip_match[1]}").country_code3
   # @geoip.country("#{ip_match[1]}").country_code2
    
    begin
     #coloca a data como chave do que e para analisar 
      begin
       # p @information_by_date
       # p ip_match[1]
        t_h_hour = @information_by_date.fetch(_data)
        # p t_h_hour
        begin
          
          t_h_ip = t_h_hour.fetch(_hour)
          begin
       
           t_hits = t_h_ip.fetch(ip_match[1])
           t_h_ip.store(ip_match[1],t_hits+1)
          rescue
          
          # p "a inserir ip na hash #{t_h_ip}"
           t_h_ip.store(ip_match[1],1)
           # p "HASH de ips #{t_h_ip}"
          end
        rescue
        t_h_hour.store(_hour,{ip_match[1]=>1})
          # p "a inserir #{ip_match[1]}" 
          # p t_hour
        end
      rescue
        # p "A Inserir DATA #{_data} #{t_h_hour} <-"
        if t_h_hour == nil
          @information_by_date.store(_data,{_hour=>{ip_match[1]=>1}})
          else
          @information_by_date.store(_data,t_h_hour)
          end
        # p @information_by_date
      end
    Debugger.debug("@information_by_date: #{@information_by_date}\n",2)
    @country_code3.store(@geoip.country("#{ip_match[1]}").country_code3, @country_code3.fetch(@geoip.country("#{ip_match[1]}").country_code3) +1 )
    @country_code2.store(@geoip.country("#{ip_match[1]}").country_code2, @country_code2.fetch(@geoip.country("#{ip_match[1]}").country_code2) +1 )
    @country_name.store(@geoip.country("#{ip_match[1]}").country_name, @country_name.fetch(@geoip.country("#{ip_match[1]}").country_name) +1 )
     rescue KeyError
        @country_code3.store(@geoip.country("#{ip_match[1]}").country_code3,1)
        @country_code2.store(@geoip.country("#{ip_match[1]}").country_code2,1)
        @country_name.store(@geoip.country("#{ip_match[1]}").country_name,1)
    end                       
  } 
  Debugger.debug("@country_code2: #{@country_code2}\n",2)
  Debugger.debug("@country_code3: #{@country_code3}\n",2)
  Debugger.debug("@country_codename: #{@country_name}\n",2)
  Debugger.debug("@information_by_date: #{@information_by_date}\n",2)
  
end


 # Para o desenho do mapa existem duas alternativas,
 # * modo gradiente
 # * modo manual ( sermos nos a definir q cor pertence a cada pais)
 # A opcao escolhida foi a manual, isto pq, a china tinha muito muito muito mais hits que qualquer outro pais
 # o que inviabilizava o uso do gradiente.
 # Percorremos a lista de paises que teem hits e atribuimos uma cor,
 # Garantidamente nunca repetimos uma cor ja atribuida 
 # verifica se  @country_hits existe  e coloca uma cor diferente para cada pais
def randomize_country_colors
  @country_colors = @country_code3.clone
  @country_colors.each{|k,v|  begin
                              my_color = ("#%06x" % (rand * 0xffffff))
                              end while @country_colors.value?(my_color)
                              @country_colors[k] = my_color
                              @country_colors[k] = "#ffffff" if "#{k}"=="A1"
                            } 
    
Debugger.debug("@country_colors: #{@country_colors}\n",2)
end

# desenha o mapa
def draw_randomize(path)
  Worldize::Countries.new.
    draw(
   @country_colors
    ).
    write(path) 

end

# Obtem o nome do ficheiro com extensao csv
#
#
#
def get_filename
  name_match = @filename.match /(\w+)\.csv/ 
  return name_match[1]
end

#
# retorna a variavel de instancia @country_name
#
def get_country_name
  return @country_name
end


#
# retorna a variavel de instancia @country_code3 ( com 3 digitos q identificam o pais)
#

def get_country_code3
  return @country_code3
end


#
# retorna a variavel de instancia @country_code2 ( com 2 digitos q identificam o pais)
#
def get_country_code2
  return @country_code2
end


#
# retorna a variavel de instancia @country_color que é uma hash com pais e cor
#
#
def get_country_colors
  return @country_colors
end

#
#
# retorna a variavel de instancia @information_by_date com a informarcao das ocorrecias
#
#
def information_by_date
  return @information_by_date
end



end # END CLASS

#
# EXMELPO DE UTILIZACAO DA CLASS
#
#
#_test_user = "pedro"
#d = Draw_map.new("report/csv/#{_test_user}/ssh.csv")
#d.process_csv_file()
#d.randomize_country_colors()
#p d.get_filename
#d.draw_randomize("report/images/#{_test_user}/#{d.get_filename}.png")
#
#
#d = Draw_map.new("report/csv/#{_test_user}/CRON.csv")
#d.process_csv_file()
#d.randomize_country_colors()
#p d.get_filename
#d.draw_randomize("report/images/#{_test_user}/#{d.get_filename}.png")
















