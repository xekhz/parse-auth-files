require 'sqlite3'
require './Cipher'
require 'base64'
class Sql_Reader_Writer
   @db
   @cipher
   
   # initializa o objecto e cria igualmente o objecto cifra
   
  def initialize(_user,nocipher=false)
    @user = _user 
    @cipher = Cipher.new if ! nocipher    
     if ! check_user(_user)  
       create_user_database(_user)
     else
       @db = SQLite3::Database.new( "report/database/#{_user}.db" )   
     end  
  end
  
  # Recebe como parametreo o nome do utilizadar e retorna um boolean mediante a condicao se true or false
  # Verifica a existencia do utilizador na BD
  # Como o nome do UTILIZADOR esta cifrado com a PASSWORD do utilizador é necessario fazer o match com o objecto cifra e verificar se obtemos a mesma string
  # ou seja o nome do utilizador
  def check_user_password(user)
    @db = SQLite3::Database.new("report/database/program/user.db" )
    
    query = "select * from user"
    @db.execute(query).each{|r|
     # p r
     # p Base64.decode64(r[1])
     # p @cipher.cipher("#{user}")
     return true if ( Base64.decode64(r[1]) ==  @cipher.cipher("#{user}"))
    }
    return false
  end

  # Pega no conteudo de um ficheiro CSV  file
  # Cifra o conteudo da linha com a password fornecida pelo utiliador e insere no SQLITE
  # (EXISTE SE QUISERMOS UMA PASSWORD PARA CADA OPERACAO, UMA PARA O LOGIN DO USER e UMA PARA CADA FICHEIRO PROCESSADO)
  #
  #  
  def service_csv_to_sql
    Dir.foreach("report/csv/#{@user}/"){|el|
   if(el != "." && el != ".." )
     lm = el.match /(.+)\.csv/ # retira o q tem extensao cap
     if lm != nil
       service = lm[1]
       printf "IMPORTING #{service} CSV to sql\n"
       File.open("report/csv/#{@user}/#{el}"){|fop|
                          begin
                             while line = fop.readline
                               lm = line.match /(.+);(.+)/
                               begin
                                 #p lm
                               #@db.execute("INSERT INTO auth_ufw (service,ip_address,timestamp) VALUES ('#{service}',#{lm[1]},#{lm[2]})")
                                 
                                 _service = Base64.encode64(@cipher.cipher("#{service}"))
                                 _ip_address =  Base64.encode64(@cipher.cipher("#{lm[1]}"))
                                 _timestamp =  Base64.encode64(@cipher.cipher("#{lm[2]}"))
                                  # p _service
                                 @db.execute("INSERT INTO auth_ufw (service,ip_address,timestamp) VALUES ('#{_service}','#{_ip_address}','#{_timestamp}')")

                               rescue Exception=>e
                                 p "sql_reader_writer.rb service_csv_to_sql : #{e}"
                               end
                             end
                          rescue
                            
                          end
                            
       }
       #depois de processado para a BD apagar o ficheiro
       File.delete("report/csv/#{@user}/#{el}")
     end
   end
    }
    
  end
  
  
 # Pega no conteudo de uma tabela com o conteudo do ficheiro CSV ou CAP e exporta para CSV  respectivamente
 # DECifra o conteudo da linha com a password fornecida pelo utiliador e escreve no ficheiro
 # (EXISTE SE QUISERMOS UMA PASSWORD PARA CADA OPERACAO, UMA PARA O LOGIN DO USER e UMA PARA CADA FICHEIRO PROCESSADO)
 #
 #  
  def sql_to_csv_service(user)
    printf"IMPORTING REMAINING CSV FILES FIRST\n"
    service_csv_to_sql
   # p "START"
    begin   
    query = "SELECT * FROM auth_ufw "
    @db.execute(query).each{|r| 
    _service = r[1]
    _ip_address = r[2]
    _timestamp = r[3]
    _f = File.open("report/csv/#{user}/#{@cipher.decipher(Base64.decode64(_service))}.csv",mode="a+")
    _f.write("#{@cipher.decipher(Base64.decode64(_ip_address))};#{@cipher.decipher(Base64.decode64(_timestamp))}\n")
      #p "#{@cipher.decipher(Base64.decode64(_service))};#{@cipher.decipher(Base64.decode64(_ip_address))};#{@cipher.decipher(Base64.decode64(_timestamp))} "
    _f.close
    }
    @db.execute("delete from auth_ufw")
    rescue Exception=>e
      p e
    end
  end
  
 # Pega no conteudo de um ficheiro CAP  file
 # Cifra o conteudo da linha com a password fornecida pelo utiliador e insere no SQLITE
 # (EXISTE SE QUISERMOS UMA PASSWORD PARA CADA OPERACAO, UMA PARA O LOGIN DO USER e UMA PARA CADA FICHEIRO PROCESSADO)
 #
 #  
  def csv_cap_to_sql
    begin 
    if File.exist?("report/csv/#{@user}/capture.cap")
      f = File.open("report/csv/#{@user}/capture.cap",mode="r")
    begin
      while line = f.readline
       lm = line.match /(\d+\.\d+\.\d+\.\d+);(.+);(\d+\.\d+\.\d+\.\d+);(.+);(.+)/
       begin
       #@db.execute("INSERT INTO capture (ip_source,port_source,ip_dest,port_dest,data)values ( '#{lm[1]}' , '#{lm[2]}' , '#{lm[3]}' , '#{lm[4]}','#{lm[5]}' )") if lm != nil
         if lm != nil 
          ip_source   = Base64.encode64(@cipher.cipher("#{lm[1]}"))
          port_source = Base64.encode64(@cipher.cipher("#{lm[2]}"))
          ip_dest     = Base64.encode64(@cipher.cipher("#{lm[3]}"))
          port_dest   = Base64.encode64(@cipher.cipher("#{lm[4]}"))
          data        = Base64.encode64(@cipher.cipher("#{lm[5]}"))         
          @db.execute("INSERT INTO capture (ip_source,port_source,ip_dest,port_dest,data)values ( '#{ip_source}' , '#{port_source}' , '#{ip_dest}' , '#{port_dest}','#{data}' )") 
         end
       rescue Exception => e
         p "sql_reader_writer : csv_cap_to_sql #{e}"
         raise "error csv cap to sql"
       end
      end
    rescue EOFError
      File.delete("report/csv/#{@user}/capture.cap")
      printf "\nDone storing cap file\n"
    
    end
    else
      p "FILE report/csv/#{@user}/capture.cap nao existe"
      return false
    end
    return true
    ensure
      if f != nil
        f.close
      end

    end
    File.delete("report/csv/#{@user}/capture.cap")
    printf "\nDone storing cap file"
  end
  
# Pega no conteudo de uma tabela com o conteudo do ficheiro CAP e exporta para cap  
# DECifra o conteudo da linha com a password fornecida pelo utiliador e escreve no ficheiro
# (EXISTE SE QUISERMOS UMA PASSWORD PARA CADA OPERACAO, UMA PARA O LOGIN DO USER e UMA PARA CADA FICHEIRO PROCESSADO)
#
#  
  def sql_to_cap_csv
  begin 
    if File.exist?("report/csv/#{@user}/capture.cap")
      printf "Importing new cap file first"
      csv_cap_to_sql
      printf "Done"
    end 
    printf "dumping cap to report/csv/#{@user}/capture.cap \n"
    File.open("report/csv/#{@user}/capture.cap",mode="w"){|fopen|
      row_array = @db.execute("select * from capture")
      row_array.each{|r|
        fopen.write(@cipher.decipher(Base64.decode64("#{r[1]}")))
        fopen.write(";")
        fopen.write(@cipher.decipher(Base64.decode64("#{r[2]}")))
        fopen.write(";")
        fopen.write(@cipher.decipher(Base64.decode64("#{r[3]}")))
        fopen.write(";")
        fopen.write(@cipher.decipher(Base64.decode64("#{r[4]}")))
        fopen.write(";")
        fopen.write(@cipher.decipher(Base64.decode64("#{r[5]}")))
        fopen.write("\n")

            } 
    }
    @db.execute("delete from capture ")  
  rescue Exception => e
    printf "#{e}\n"
    @db.execute("delete from capture ")  
  end
  end
  
  # Apaga o login do utilizador
  #
  #
  #
  def delete_user_login(user)
    begin 
    @db1 = SQLite3::Database.new( "report/database/program/user.db" )
    _encoded_user = Base64.encode64(@cipher.cipher(user))
    p _encoded_user
    @db1.execute("DELETE FROM user WHERE username='#{_encoded_user}' ")
    printf("user deleted #{user}")
  rescue Exception=>e
    #p e
  end
  end
  
  # cria um utilizador na BD
  # 
  #
  def create_user(user)
    create_user_database(user)
  end
  
  # Apaga toda a informacao do utilizador
  # 
  #
  def delete_user
    begin 
    return File.delete("report/database/#{user}.db")
    rescue Exception => e
      p "Sql_Reader_Writer : func delete_user #{e}"
    end
  end
  
  
  # Verifica se o user existe
  #
  #
  # return boolean
  def check_user(user)
    begin 
    return File.exist?("report/database/#{user}.db")
      rescue Exception => e
        p " Sql_Reader_Writer : check_user  #{e}"
        return false
    end 
  end
  
  # cria uma BD por cada user
  # cria as tabelas necessarias
  #
  def create_user_database(user)  
  begin
    @db = SQLite3::Database.new( "report/database/#{user}.db" ) 
    
    #create table auth_ufw
    auth_ufw = "CREATE TABLE auth_ufw (
          id  INTEGER PRIMARY KEY AUTOINCREMENT,
          service varchar(15),
          ip_address varchar2(15),
          timestamp varchar2(20)
        );  
    "
    @db.execute(auth_ufw)
    p "done creatig table auth_ufw"
    
    capture = "CREATE TABLE capture (
    id   INTEGER PRIMARY KEY AUTOINCREMENT ,
    ip_source varchar(15),
    port_source varchar2(15000),
    ip_dest varchar2(15000),
    port_dest varchar2(15000),
    data varchar2(15000)
  );  
"
    @db.execute(capture)
      p "done creating table capture"
  
  
     
    user_table = "CREATE TABLE user (
       id   INTEGER PRIMARY KEY AUTOINCREMENT ,
       username varchar(15),
       userpass varchar2(15)
     );  
   "
    @db.execute(user_table)
    
   p "done creating table user"
     
    if ! File.exist?("report/database/program/user.db")   
      @db1 = SQLite3::Database.new( "report/database/program/user.db" )
        user_table = "CREATE TABLE user (
         id   INTEGER PRIMARY KEY AUTOINCREMENT ,
         username varchar(150)
       );  
      "   
      @db1.execute(user_table)
      p "done creating table for user autentications"
    end
    @db1 = SQLite3::Database.new( "report/database/program/user.db" )
  
    cipher_username = Base64.encode64(@cipher.cipher("#{user}"))
    query = "INSERT INTO user (username) values ('#{cipher_username}')"
    @db1.execute(query)
    p "user #{user} inserted\n"  
   
    
  rescue   Exception => e 
    p "Sql_Reader_Writer : create_user_database  #{e}"
  end
    #db.execute(auth_ufw)
    
  end
  
  
end



############END CLASS##############

#s3 = Sql_Reader_Writer.new("tttt")
#s3.csv_cap_to_sql()
#s3.sql_to_cap_csv
# s3.service_csv_to_sql


