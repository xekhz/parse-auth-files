
# No initio verifcar as condicoes
# a) Directoria report/{csv,images} existe
# b) o user existe ou cria o user na BD
#  b.1) criar a dir report/{csv,images}/USER

require './Sql_Reader_Writer.rb'
require 'fileutils'

class Program

def initialize
end
#
# Funcao para ler um char do teclado e retornar imediatamente
#
#
def get_single_char
  printf "> "
  tty_param = `stty -g`
  system 'stty raw'
  input_single_char = IO.read '/dev/stdin', 1
  system "stty #{tty_param}"
#  print "#{input_single_char}\n"

return input_single_char

end 

#
# verifica a condicao obrigatoria para ser user
#
def user_check(_user)
  (printf("\nUser must be > 3 chars\n") ; raise "\nErro no nome de utilizador tem de conter > 3 chars\n") if _user.size<4
end

def input_length_check(input,message)
  (printf("\n#{message}\n") ; raise "\n#{message} \n") if input.size<4
end


#
# Desenho do menu de login
#
def start_menu
  printf "\nPrograma para a disciplina de LPD\n"
  printf "Choose one option\n"
  printf "------------------------------------\n"
  printf "1) Insert user\n"
  printf "2) Login user\n"
  printf "3) Delete user\n"
  printf "0) Exit\n"
end


#
# desenho do user menu
# Cada opcao do menu instancia uma classe que pretende executar o descrito.
#
def user_menu(user)
  printf "\Logged in\n"
while true
  printf "Choose one option\n"
  printf "------------------------------------\n"
  printf "1) Scan open ports on address\n"
  printf "2) Sniff network interfaces \n"
  printf "3) Show local tcp socket state\n"
  printf "4) Build CSV from LOG\n"
  printf "5) Build PDF \n"
  printf "6) Store cap in sqlite \n"
  printf "7) Dump cap from sqlite to csv\n"
  printf "8) Store service log or fw log in sqlite\n"
  printf "9) Dump service log or fw log from sqlite in csv\n"
  printf "0) Exit\n"
  printf "(user_menu) #{user} >"
  c = get_single_char
#  p c
 
  case c
    when '1'
  begin
    require './MachineScan.rb'
    printf "\nInput the address to portscan (ex: www.sapo.pt ) (ex: 192.168.0.251): "
    address = gets
    address[-1]=''
    printf "\nPlease input start port:"
    start_port = gets
    start_port[-1]=''
    start_port = start_port.to_i
    printf "\nPlease input end port:"  
    end_port = gets
    end_port[-1]=''
    end_port = end_port.to_i
    printf"\n"
    (tmp_port = start_port ; start_port = end_port ; start_port = tmp_port )if start_port > end_port      
    start_port = 1 if start_port < 1
    end_port = 1024 if end_port < 1  
    m = MachineScan.new("#{address}",start_port,end_port)
     printf "Searching open ports in #{address}\n"
     m.run
     m.get_report   
      # call_portscaner
  rescue Exception => e
    raise "call_portscaner #{e} "
  end
    when '2'
      require './Csv_writer.rb'
      require './Sniffer.rb'
      printf "\n Number of seconds to sniff : "
      num_seconds = gets
      num_seconds[-1]=''
      num_seconds = num_seconds.to_i
      
      printf "\n Max packects in capture : "
      max_pkt = gets
      max_pkt[-1]=''
      max_pkt = max_pkt.to_i  
      
      max_pkt = 1000 if max_pkt < 1
      num_seconds = 10 if num_seconds < 1
      
      csv = Csv_writer.new(user)
      s = Sniffer.new(max_pkt,num_seconds)
      s.run
      #p s.pcap_array_format
      csv.pcap_writer_array(s.pcap_array_format)
      printf "Pcap writen\n"
    when'3'
    printf "\nShowing local tcp socket state:\n "
    system('ss -tn')
    printf "\n\n "
    when'4'
          # BUILD CSV FROM LOG FILE
      begin
          require './log_analyzer.rb'
          printf "\nInput filepath to process ( #{@logs_location}/#{user}/auth.log ) : "
          log_file_path = gets
          log_file_path[-1]=''
          (log_file_path = "#{@logs_location}/#{user}/auth.log" )if log_file_path == ''       
          input_length_check(log_file_path,"The path must be > 3 chars")
          (raise "#{log_file_path} does not exist:\n") if ! File.exist?("#{log_file_path}")
          printf("\n The file is type LOG or type UFW\n")
            printf("Press A for type LOG\n")
            printf("Press B for type UFW\n")
            c = get_single_char()
          while( c != 'A'  &&  c != 'B' )
            printf("\nPress A for type LOG\n")
            printf("Press B for type UFW\n")
            c = get_single_char()
          end
          
           case c
           when 'A'
             printf "\nBuild CSV for SERVICE LOG FILE"
             l = Log_analyzer.new("#{log_file_path}",1)
             l.services()
             l.insert_new_regexp_service("ssh",Regexp.new('Failed password',Regexp::IGNORECASE))
             
             printf "\n Do you want to parse another service (ssh is always parsed): Y/N"
             c = get_single_char()
           while c != 'N' && c != 'n' 
             printf "\n Please insert service to parse (ssh is always parsed): "
              service_to_parse = gets
              service_to_parse[-1]=''
             
             if service_to_parse != ""
               printf "\n Please insert expression to parse in service #{service_to_parse}: "
               expression_to_parse = gets
               expression_to_parse[-1]=''
              
                while expression_to_parse == ""
                  printf "\n Please insert expression to parse in service #{service_to_parse}: "
                  expression_to_parse = gets
                  expression_to_parse[-1]=''
                end
             else
                printf "service cant be empty\n"
                  
             end
             l.insert_new_regexp_service("#{service_to_parse}",Regexp.new("#{expression_to_parse}",Regexp::IGNORECASE))  
             printf "\n Do you want to parse another service (ssh is always parsed): Y/N"
             c =  get_single_char()                        
           end 
             #l.insert_new_regexp_service("cron",/ Failed password/)
             l.parse_log_file()
             require './Csv_writer.rb'
             csv = Csv_writer.new(user,1)
             csv.detections(l.get_detections)
             printf "\nCSV written in #{@csv_location}/#{user}\n"                          
           when 'B'
             printf "\nBuild CSV for UFW LOG FILE"
             ll = Log_analyzer.new("#{log_file_path}",1)
             ll.services()
             ll.insert_new_regexp_service("UFW",/ BLOCK/)
             ll.parse_firewall_file()
             require './Csv_writer.rb'
             csv = Csv_writer.new(user,1)
             f_h = ll.get_firewall_detections
             csv.detections(f_h.first[1])
             printf "\nCSV written in #{@csv_location}/#{user}\n"               
          end
      rescue Exception =>e
        printf "#{e}"
      end 
     when '5'
      begin
        not_empty = false
        Dir.foreach("#{@csv_location}/#{user}/"){|elem|
          em = elem.match /(.+).csv/
          if em != nil
            not_empty = true
          end
        }
        (raise printf "\nNot one CSV found, please use option 4 for building csv before building the PDF\n") if ! not_empty
        
        printf "\nInput PDF filename (/tmp/#{user}-report.pdf): "
        pdf_file_path = gets
        pdf_file_path[-1]=''
        (pdf_file_path = "/tmp/#{user}-report.pdf" )if pdf_file_path == ''       
        input_length_check(pdf_file_path,"The path must be > 3 chars")
       
        
      printf "\nBaking PDF\n"
      #####
      require './Pdf_report.rb'
        p = Pdf_report.new("#{pdf_file_path}","#{user}")
        p.get_services
        p.start_document()
        p.writer_all_log
        p.writer_by_date
        p.do_pdf_file
      #####
      printf "\nPDF cooked\n"
    # call log analizer
      rescue Exception=> e
        p e
      end
      when '6'           
       begin
         printf"\nStoring cap file #{user}\n"
         s3 = Sql_Reader_Writer.new(user)
         s3.csv_cap_to_sql()
       rescue Exceptio => e
         p e
       end
       when '7'
        printf"\n From sql cap to csv file #{user}\n"
        s3 = Sql_Reader_Writer.new(user)
        s3.sql_to_cap_csv()
      when '8'
        printf"\n From csv file to sql #{user}\n"
        s3 = Sql_Reader_Writer.new(user)
        s3.service_csv_to_sql
      when '9'
        begin 
       
        s9 = Sql_Reader_Writer.new(user)
        s9.sql_to_csv_service(user)
        rescue Exception => e
          p e      
        end
  when '0'
    return
  end
end
end


trap "SIGINT" do
  puts "Exiting"
  exit 130
end


def run

@report_location = "report"
@database_location = "#{@report_location}/database"
@csv_location = "#{@report_location}/csv"
@images_location = "#{@report_location}/images"
@logs_location = "#{@report_location}/logs"

while true
begin  
start_menu
case get_single_char
when '1'
  #cria o utilizador
  printf "\nInsert desired user name: "
  user = gets
  (printf("\nUser name must be > 3 chars\n") ; raise "\nError must be  > 3 chars\n") if user.size<4
  user[-1]=''
  printf "\nA checking user availability: #{user}\n"
  if ! File.exist?("#{@database_location}/#{user}.db")
    printf "\nInserting user: #{user}\n"
    d = Sql_Reader_Writer.new("#{user}")
    if d.check_user(user)
      printf "Building workpath"
      Dir.mkdir("#{@csv_location}/#{user}")
      Dir.mkdir("#{@images_location}/#{user}")   
      Dir.mkdir("#{@logs_location}/#{user}")   
      end
    else
     printf "\nO User already exists : #{user}\n" 
     raise "\n ### Error creating user #{user} ### \n"
  end
when '2'
  #efectua o login
  printf "\nLogin:"
  user =  gets
  
  user_check(user)
  user[-1]=''
    if File.exist?("#{@database_location}/#{user}.db")
    #verifica a password
      d = Sql_Reader_Writer.new("#{user}") 
         user_menu(user) if d.check_user_password("#{user}")     
    else
      printf"No user with username: #{user}"
    end
    when '3'
    printf "\nUser to delete: "
    user  =  gets
    user[-1]=""
    user_check(user)
  if File.exist?("#{@database_location}/#{user}.db")
     #verifica a password
       d = Sql_Reader_Writer.new("#{user}") 
      begin  
        if d.check_user_password("#{user}")
          d.delete_user_login(user);
          FileUtils.rm_rf("report/csv/#{user}") ;
          File.delete("report/database/#{user}.db");
          FileUtils.rm_rf("report/images/#{user}") ;
          FileUtils.rm_rf("report/logs/#{user}")      
         end
      rescue Exception=>e
        #p e 
      end
      printf "\ndone\n"
      else
       printf"No user with username: #{user}"
     end
      
when '0'
  printf "exiting"
  exit
end
rescue
end
end
end

end

p = Program.new
p.run

exit
#
#
#_user =  "pedro"
# 
#
#begin
#Dir.mkdir("report/csv/#{_user}",0770)
#printf("A criar a directoria : report/csv/#{_user}\n")
#rescue  Errno::EEXIST
#printf("A directoria : report/csv/#{_user} ja existe\n")  
#end
#
#begin 
#Dir.mkdir("report/images/#{_user}",0770)
#printf("A criar a directoria : report/images/#{_user}\n")
#rescue Errno::EEXIST
#printf("A directoria : report/images/#{_user} ja existe\n")
#end
#
#require './log_analyzer.rb'
#
########################### PARA O EWF ########
#ll = Log_analyzer.new("ufw.log",1)
#ll.services()
#
#ll.insert_new_regexp_service("UFW",/ BLOCK/)
#ll.parse_firewall_file()
##p ll.get_firewall_detections
##p "##FIM##"
#require './Csv_writer.rb'
##
#csv = Csv_writer.new(_user,1)
#f_h = ll.get_firewall_detections
#
#csv.detections(f_h.first[1])
#
#p "CSV escritos"
##exit
###############################################
#
#
##
## Questiona o utilizar sobre qual o ficheiro a analisar
##
#
#l = Log_analyzer.new("auth.log.4",1)
#l.services()
#
##
## Questiona qual o servico ou servicos devem ser tidos em conta na analise do ficheiro para a determinacao das intrusoes
##
#
#l.insert_new_regexp_service("ssh",/ Failed password/)
##l.insert_new_regexp_service("UFW",/ BLOCK/)
##l.insert_new_regexp_service("UFW",/ kernel/)
## l.insert_new_regexp_service("ssh",/ BREAK/)
##l.insert_new_regexp_service("CRON",/ Failed password/)
## l.insert_new_regexp_service("FTP",/ ATTEMPT/)
## l.insert_new_regexp_service("RAIOS",/ ATTEMPT/)
#l.parse_log_file()
#
## p l.get_detections()
#
#require './Csv_writer.rb'
#
#csv = Csv_writer.new(_user,1)
#csv.detections(l.get_detections)
#p "CSV escritos"
##
## SNIFFER
##
#
## PORTSCAN
##
##
#
## gera relatorio com base nos CSV
