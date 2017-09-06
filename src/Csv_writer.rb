require './Debugger.rb'

#
#
#
# apagar os csv q estao nas directorias
#
#
#
#

class Csv_writer

  @user
  def initialize(user, debug_level=0)
    Debugger.set_level(debug_level)
    @user = user
  end
  
  

  #
  # ESCREVE EM FORMATO CSV MAS COM UM CAMPO ExTRA 
  # 
  #
  def pcap_writer(pcap_hash_format)
    pcap_hash_format.each{|port,src_dest_ip_array|
     # Debugger.debug("port_detected:#{port} #{src_dest_ip_array}\n",1)
      capture_number=1
      src_dest_ip_array.each{|element| 
          #csv_line = "'#{capture_number}';'#{port}';'#{element.fetch("src_ip")}';'#{element.fetch("dst_ip")}';'#{element.fetch("data")}'\n"
          csv_line = "'#{capture_number}';'#{port}';'#{element.fetch("src_ip")}';'#{element.fetch("dst_ip")}';'#{element.fetch("data")}'\n"

          Debugger.debug(csv_line,0)
        File.open("report/csv/#{@user}/#{port}.cap",mode="a+"){|f| f.write(csv_line)}
        capture_number+=1
      }
    }
  end
  
  def pcap_writer_array(pkt_array)   
    File.open("report/csv/#{@user}/capture.cap",mode="a+"){ |f| 
                                                                  pkt_array.each{|element|  f.write(element) }
                                                           }    
  end
  
  # Recebe uma hash e imprime para CSV
  # FORMATO HASH 
  # { "ssh"=>{
  #      "177.154.231.59"=>
  #                         { 
  #                           "hits"=>2, 
  #                           "when"=> [ #<MatchData "Feb 22 07:13:03" 1:"Feb 22 07:13:03">, #<MatchData "Feb 22 08:06:27" 1:"Feb 22 08:06:27"> ]
  #                         }
  # }
  #
  #
  #
  #  
  def detections(det)
    begin
     
      #File.open("report/csv/#{@user}/detections.csv"){|f| p f }
        # abre o ficheiro com nome do protocolo
      Debugger.debug("\nSumario de deteccoes:\n",1)
      Debugger.debug("\n#####################\n\n",1)
      
      det.each{ |k,v| 
        #File::CREAT|File::TRUNC|File::RDWR, 0644
                      File.open("report/csv/#{@user}/#{k}.csv",mode="a+"){|f| 
                                                                                                              v.each{ |kk,vv| 
                                                                                                                              vv.each{ |kkk,vvv | 
                                                                                                                                                  if "#{kkk}"=="hits" then 
                                                                                                                                                    Debugger.debug("#{kk} : #{kkk} = #{vvv}\n",1) 
                                                                                                                                                  else vvv.each{|el| 
                                                                                                                                                        f.write("'#{kk}';'#{el}'\n")
                                                                                                                                                          } 
                                                                                                                                                  end
                                                                                                                                    }
                                                                                                                    }
                                                                                                         }
               }
    
    ensure
    Debugger.debug("\n#####################\n",1)
      #_myfile.close
    end
    
  end
  
#end CLASS Csvwriter
end