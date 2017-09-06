require 'prawn'
require 'geoip'
require './Debugger.rb'
require './Draw_map.rb'
require 'iso_country_codes' 
# corrigido irao, vietnam e koreias
class Pdf_report
  @user
  @pdf
  @filename 
  @document_title
  @detections
  @geoip
  
  def initialize(f,user)
  @pdf = Prawn::Document.new
  @pdf.define_grid(:columns=>5, :rows=>32, :gutter=>2)
  @filename = f
  @document_title =   "NETWORK ANALYSIS AND FAILED LOGIN ATTEMPTS" 
  @user = user
  @detections_code2 = Hash.new
  @detections_code3 = Hash.new
  @detections_name = Hash.new
  @detections_colors = Hash.new
  @information_by_date = Hash.new
  Debugger.set_level(3)
  end
  #
  # Initializa o objecto que gera o pdf
  # 
  #
  #
  #
  #
  def start_document
#       @geoip = GeoIP.new('GeoIP.dat')
        @geoip = GeoIP.new('GeoLiteCity.dat')
        @pdf.font_size 16    
        @pdf.move_down 250
        @pdf.stroke_horizontal_rule
        @pdf.move_down 7  
        @pdf.text(@document_title, :align => :center)
        @pdf.stroke_horizontal_rule  
        @pdf.start_new_page
        @pdf.start_new_page
   #     @pdf.grid.show_all # MOSTRAR A GRELHA PARA ORIENTACAO
         
  end
  
  #
  # Escreve o mapa no pdf e o acumulado dos hits por pais em cada servico analisado
  #
  #
  #
  #
  def writer_all_log
    begin
    
    #@pdf.stroke_axis
    #self.line_with = 10
    #@pdf.fill_gradient([50,300] , [250,0] , 'ff0000', '00ff00')
    #@pdf.fill_rectangle([50,300], 500 , 10)
    #@pdf.font_size 10
    
    @pdf.font_size 14    
    #@pdf.stroke_horizontal_rule
    @pdf.move_down 7 
   # @pdf.text("NUMBER OF HITS PER SERVICE:",:align => :left)
    @pdf.move_down 10
    @pdf.font_size 12
    @pdf.text("HITS PER SERVICE AND COUNTRY",:align => :center)
    # certifica q os csv estao carregados para uma hash e posterior processamento
 
   
    
    while t = @detections_name.shift do
      line_iterator = 14
      service = t[0]

      #hash table preparada para ir buscar o nome das bandeiras
      # 
      # p("70: INICIO DO WRITE ALL LOG #{@detections_colors}\n")
      detections_colors = @detections_colors.dup
      tc = detections_colors.fetch(service) #tc contem as cores de cada pais
      # p "72: #{detections_colors}"
      #line_iterator para comecar a escrever debaixo do mapa pintado
      @pdf.start_new_page
      service_string = service
      service_string = "firewall bloked port #{service}" if service.match /\d+/
      @pdf.text("SERVICE #{service_string} - ATTEMPTS:".upcase,:align => :left)
      @pdf.line_width(1)
      @pdf.move_down 1
      @pdf.stroke_horizontal_rule
      @pdf.move_down 1
      @pdf.image("report/images/#{@user}/#{service}.png", :position=>:center , :width=>400)
      @pdf.stroke_horizontal_rule
      #@pdf.font("Helvetica", :size=>12)
      table_array = Array.new
      # ORDENAR OS ITENS PELO NOME(CHAVE)
      # "TAMANHO #{t[1].size}"
      if ((t[1].size) < 1) then
        @pdf.move_down 100
        @pdf.text("<b>NOTHING DETECTED</b>",:align=>:center,:overflow=>:shrink_to_fit,:size=>12,:inline_format=>true)
      end
      
      # ordenar por o numero de hits
      t[1] = t[1].sort_by{|k,v| v }.reverse
      t[1].each{ |k,v| 
        #@pdf.grid(line_iterator,0).show
        #@pdf.grid(line_iterator,1).show
        #@pdf.grid(line_iterator,2).show
        #@pdf.grid(line_iterator,3).show
        @pdf.grid(line_iterator,0).bounding_box {
          #country name
          @pdf.text("#{k}",:align=>:right,:overflow=>:shrink_to_fit)
          # p "#{k} "
          } 
          @pdf.grid(line_iterator,1).bounding_box {
            #country hits #{Prawn::Text::NBSP*3}
            @pdf.text("#{v}",:align=>:center,:overflow=>:shrink_to_fit)
            # p "#{v}\t"
          } 
          @pdf.grid(line_iterator,2).bounding_box {
            
            #country flag
            begin
           
            name_match = k.match /(\w+),,.+/
            
            if name_match.to_s.size>0
             code = IsoCountryCodes.search_by_name(name_match[1])
             else
              code = IsoCountryCodes.search_by_name(k)
            end
            flag = (code[0].alpha2).downcase
            # p " #{flag} "
            rescue
            flag="default"
            end
            #flag=(t2[1].shift)[0]
            #flag.downcase
            image_default = "flags_iso/default.png"
            image = "flags_iso/128/#{flag.downcase}.png"
            image = image_default if ! File.exist?(image)
            @pdf.move_up 5
            @pdf.image(image,:width=>20) 
         }
         @pdf.grid(line_iterator,3).bounding_box {
            #country color
            begin 
              name_match = k.match /(\w+),,.+/
             # p "137: #{k}" 
              if name_match.to_s.size>0
               code = IsoCountryCodes.search_by_name(name_match[1])
              else
              #  p "141: searching for #{k}"
               code = IsoCountryCodes.search_by_name(k)
              # p "143: #{code[0].alpha3}"
              end
             
            color = tc.fetch(code[0].alpha3)
            # p "146: #{color}"
            rescue
            color = "#ffffff"
            end
            # p "147: #{color}\n"
            color[0]='' # PROBLEMA ESTRANHO NO RUBY APESAR DE SE USAR UM CLONE DE UMA VAR DE INSTANCIA ESTA ALTERACAO E RESCRITA NA VARIAVEL DE INSTANCIA. TUDO OQUE FOR PINTADO PARA A FRENTE N SE RETIRA O #
            @pdf.fill_color = color.to_s

            @pdf.fill_rectangle [0,13], 60 , -10
            @pdf.fill_color = "000000"
#            @pdf.text "#{color}"
           } 
         if line_iterator < 27 then
          line_iterator=line_iterator+1
         else
            line_iterator = 1
            @pdf.start_new_page
         end  
      } #fim do t.each 
  
    end #fim do while
#    @pdf.font("Helvetica", :size=>12)
    @pdf.start_new_page
   # @pdf.text "#########FIM DA IMPRESSAO ###############"
    ensure
    
    end
  end
  
  #
  # Escreve o mapa no pdf e o discriminado por hora e dia dos hits por pais em cada servico analisado
  #
  #
  #
  #
  
  def writer_by_date
    
    @pdf.font_size 14    
        #@pdf.stroke_horizontal_rule
        @pdf.move_down 7 
     #   @pdf.text("NUMBER OF HITS PER SERVICE:",:align => :left)
        @pdf.move_down 10
        @pdf.font_size 12
        @pdf.text("HITS PER SERVICE / DATE / COUNTRY - IP ADDRESS",:align => :center)
        # certifica q os csv estao carregados para uma hash e posterior processamento
        # p @information_by_date
        #p "CORES DE CADA PAIS #{@detections_colors}"  #tc contem as cores de cada pais
        # p("182: INICIO DO WRITE BY DATE #{@detections_colors}\n")
        while t = @information_by_date.shift do
          service = t[0]
          _data_hash = t[1]
          line_iterator = 14
                service = t[0]
                @pdf.start_new_page
                service_string = service
                service_string = "firewall bloked port #{service}" if service.match /\d+/
                @pdf.text("SERVICE #{service_string} - ATTEMPTS:".upcase,:align => :left)
                @pdf.line_width(1)
                @pdf.move_down 1
                @pdf.stroke_horizontal_rule
                @pdf.move_down 1
                @pdf.image("report/images/#{@user}/#{service}.png", :position=>:center , :width=>400)
                @pdf.stroke_horizontal_rule
                table_array = Array.new
                # ORDENAR OS ITENS PELO NOME(CHAVE)
                # "TAMANHO #{t[1].size}"
                if ((t[1].size) < 1) then
                @pdf.move_down 100
                @pdf.text("<b>NOTHING DETECTED</b>",:align=>:center,:overflow=>:shrink_to_fit,:size=>12,:inline_format=>true)
                end
                first = true
                t[1].each{ |k,v|
                    # p "#{k} #{v}"
                          #ESCREVE O DIA k
                          @pdf.move_down 5
                          # p "DIA: #{k}"
                          (first = true ; line_iterator=1)if line_iterator <4
                          (  @pdf.start_new_page; line_iterator=1) if ! first 
                          first = false
                          @pdf.grid(line_iterator,0).bounding_box {   
                              @pdf.text("<b>#{k}</b>",:align=>:left,:overflow=>:shrink_to_fit,:size=>12,:inline_format=>true)
                          }
                          # v = {\"12\"=>{\"177.154.231.72\"=>1}, \"13\"=>{\"177.154.231.72\"=>2}
                          line_iterator=line_iterator+1
                           #vv = v.clone
                           v = v.sort_by{|a,b|a}
                           # p "COMPARAR v #{v}"
                           # p "COM #{vv}"
                           v.each{ |hora,h_ip|
                              # p "DIA #{k} Hora #{hora} HASH IP #{h_ip}"
                             @pdf.grid(line_iterator,0).bounding_box {
                              @pdf.text("<b>From #{hora} O\'clock until +1 hour </b>",:align=>:left,:overflow=>:shrink_to_fit,:size=>12,:inline_format=>true)
                             }
                              h_ip = h_ip.sort_by{|a,b|b}.reverse
                             line_iterator=line_iterator+1
                              h_ip.each{ |ip,hits|
                                #line_iterator=line_iterator+1 
                                _ip_information = @geoip.country(ip)
                                
                                ############################ COUNTRY NAME ################################
                                @pdf.grid(line_iterator,0).bounding_box {
                                  @pdf.text("#{_ip_information.country_name}",:align=>:right,:overflow=>:shrink_to_fit,:size=>10,:inline_format=>true)
                                  # p "IP: #{_ip_information.country_name} HITS:#{hits}"
                                  }
                                @pdf.grid(line_iterator,1).bounding_box {
                                  if _ip_information.city_name != ""
                                        @pdf.text("#{_ip_information.city_name}",:align=>:center,:overflow=>:shrink_to_fit,:size=>10,:inline_format=>true)
                                  else
                                    @pdf.text("---",:align=>:center,:overflow=>:shrink_to_fit,:size=>10,:inline_format=>true)
                                  end
                                          #p "IP: #{_ip_information}"
                                        }
                                ############################ IP OU NOME ######################################     
                                @pdf.grid(line_iterator,2).bounding_box {
                                        @pdf.text("#{ip}",:align=>:center,:overflow=>:shrink_to_fit,:size=>10,:inline_format=>true)
                                          #p "IP: #{_ip_information}"
                                        }

                                 ############################ HITS ################################ 
                                @pdf.grid(line_iterator,3).bounding_box {
                                       @pdf.text("#{hits}",:align=>:center,:overflow=>:shrink_to_fit,:size=>10,:inline_format=>true)
                                      # p "IP: #{_ip_information.country_name} HITS:#{hits}"
                                     }
                               
                                ############################ FLAG ################################
                                @pdf.grid(line_iterator,3).bounding_box {
                                  
                                  #country flag
                                  begin
                                    # p "SEARCHING FOR FLAG OF #{_ip_information.country_name}" 
                                    name_match = _ip_information.country_code3.match /(\w+),,.+/                                     
                                  
                                  if name_match.to_s.size>0
                                   code = IsoCountryCodes.search_by_name(name_match[1])
                                   else
                                    code = IsoCountryCodes.search_by_name(_ip_information.country_name)
                                  end
                                  flag = (_ip_information.country_code2).downcase
                                  # printf " FLAG: #{flag} \n"
                                  rescue
                                  flag="default"
                                  end
                                  #flag=(t2[1].shift)[0]
                                  #flag.downcase
                                  image_default = "flags_iso/default.png"
                                  image = "flags_iso/128/#{flag.downcase}.png"
                                  image = image_default if ! File.exist?(image)
                                  @pdf.move_up 5
 
                                  @pdf.image(image,:width=>20) 
                               }
                                  
                                     
                                ############################ COLOR ################################
                                  @pdf.grid(line_iterator,4).bounding_box {
                                   #country color
                                   # printf("287: #{service} #{_ip_information.country_code3} #{@detections_colors.fetch(service)}\n")
                                   begin
                                     
                                     #Debbuger.debug("SEARCHING FOR COLOR OF #{_ip_information.country_code3} SERVICE: #{service} #{@detections_colors.fetch(service)}",0) 
                                     name_match = _ip_information.country_code3.match /(\w+),,.+/                                     
                                     
                                     if name_match.to_s.size>0
                                      code = IsoCountryCodes.search_by_name(name_match[1])
                                     else
                                      code = IsoCountryCodes.search_by_name(_ip_information.country_name)
                                     end                                    
                                   #Debugger.debug("color : #{@detections_colors.fetch(service).fetch(code[0].alpha3)}\n",0)
                                   color = @detections_colors.fetch(service).fetch(code[0].alpha3)
                                   rescue
                                   #Debugger.debug("NO COLOR",0) 
                                   color = "ffffff"
                                   end
                                   #printf" COLOR: #{color}\n"
                                   #color_match = color.to_s.match /.(.+)/
                                   #Debugger.debug("A COR E: #{color_match[1]}",0)
                                  
                                   @pdf.fill_color = color
                                   @pdf.fill_rectangle [0,13], 60 , -10
                            
                                   @pdf.fill_color = "000000"
                       #            @pdf.text "#{color}"
                                  } 
                                   line_iterator=line_iterator+1
                             }
                              
                             if line_iterator < 28 then
                             #line_iterator=line_iterator+2
                              line_iterator=line_iterator+1
                            else
                              line_iterator = 1
                              @pdf.start_new_page
                            end
                             
                             
                           }# fim v.each
                           ###line_iterator=line_iterator+2  
                           if line_iterator < 29 then
                             line_iterator=line_iterator+2
                             # line_iterator=line_iterator+1
                            else
                              line_iterator = 1
                               @pdf.start_new_page
                            end
                            
                          } # FIM t[1].each
                
      

        end # FIM DO WHILE
  end 
  
  def do_pdf_file
    @pdf.render_file(@filename)
  end
  
  # Verifica a existencia do ficheiro csv e para cada existencia retira a informacao e gera os mapas 
  # a incluir no pdf
  # mapa de temperatura e mapa de ocorrencias
  #
  
  def get_services
    service_files = Array.new()
    Dir.foreach("report/csv/#{@user}"){|sf|
      name_match = sf.match /(\w+).csv/
      if name_match
       #service_files << sf
       #@detections.store(name_match[1],Hash.new) 
       d = Draw_map.new("report/csv/#{@user}/#{sf}")
       d.process_csv_file()
       d.randomize_country_colors()
       d.draw_randomize("report/images/#{@user}/#{name_match[1]}.png")
       # p "### INSTANCIAS VARIAVEIS GLOBAIS E DEPOIS PROCESSAR E FAZER O PDF."
       # p d.get_country_code2
       # p d.get_country_code3
       # p d.get_country_name
       @detections_code2.store(name_match[1],d.get_country_code2)
       @detections_code3.store(name_match[1],d.get_country_code3)
       @detections_name.store(name_match[1],d.get_country_name)
       @detections_colors.store(name_match[1],d.get_country_colors())
       @information_by_date.store(name_match[1],d.information_by_date())
        #p "#START#"
        #p @detections_code3
        #p @information_by_date
        #p @detections_name
        # p "381: #{@detections_colors}"
        #p "#END#"
       
    end
    }
  end
  
  
  
  
end

#
# EXEMPLO DE UTILIZACAO
#
#
#p = Pdf_report.new("/tmp/TESTE.PDF","rebola")
#p.get_services
#p.start_document()
#p.writer_all_log
#p.writer_by_date
#p.do_pdf_file

#f = Pdf_report.new("FIREWAL.PDF","pedro")
#f.get_services
#f.start_document()
#f.writer_all_log
#f.writer_by_date
#f.do_pdf_file



