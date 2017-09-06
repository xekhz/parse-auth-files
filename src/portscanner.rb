require 'celluloid'
require 'socket'

class ScanPort
  include Celluloid
  #
  # Initializa o object
  # requisito porto de inicio e fim
  #
  #
  def initialize(start_port, end_port, host)
    @start_port = start_port
    @end_port = end_port
    @host = host
    @open_ports = Array.new
  end

  def run
    until @start_port == @end_port do
      scan @start_port
      @start_port += 1
    end
   end

  def get_open_ports()
    return @open_ports
  end
  
  #efectua o scan ao porto em questao.
  def scan(port)
      begin
        sock = Socket.new(:INET, :STREAM)        #build the socket
        raw = Socket.sockaddr_in(port, @host)

        puts "#{port} open." if sock.connect(raw)
        @open_ports << port if sock.connect(raw)
      rescue
        if sock != nil
          sock.close
        end
      end
    end
end

# executa o porscan multiithread
# retorna a lista de portos abertos
def main
  host = ARGV[0]
  start_port = ARGV[1].to_i
  end_port = ARGV[2].to_i
  open_ports_list = Array.new
  segment_size = 100

  until start_port >= end_port do
  sp = ScanPort.new start_port, start_port + segment_size, host
  sp.async.run
   if (sp.get_open_ports.size > 0) then
      p sp.get_open_ports
      open_ports_list = open_ports_list + sp.get_open_ports
    end  
  start_port += segment_size
  # thread de segment_size em segment_size
  end
  p open_ports_list
end

main
