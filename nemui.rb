require 'net/telnet'

class IX2015
  @session = nil
  COLUMN = %w(id password host ike_policy_name key ike_proposal_name autokey_policy_map_name access_list_name sa_proposal_name)

  def initialize(&block)
    COLUMN.each do |i|
      eval "
        def #{i}(#{i})
          @#{i} = #{i}
        end
      "
    end
    instance_eval(&block)
    self
  end

  def login
    if @session.nil?
      begin
        @session = Net::Telnet.new("Host" => @host, "Timeout" => 10)
      rescue => e
        puts e
        exit
      end
      @session.login(@id, @password)
      if @session.cmd("enable-config") =~ /svintr-config/
        @session.cmd("svintr-config")
      end
      while_exit
      @session.cmd("enable-config")
      exec "term len 0"
    end
    self
  end

  def logout
    while_exit
    self
  end

  def tunnel?(interface_number)
    tunnel = exec("show interfaces Tunnel#{interface_number}")
    tunnel =~ /^Interface Tunnel#{interface_number.split(".").first}\.0 is (.+)$/
    if $1 == "down"
      false
    else
      true
    end
  end

  def update_ip(new_ip)
    exec "ike policy #{@ike_policy_name} peer #{new_ip} key #{@key} mode aggressive #{@ike_proposal_name}"
    exec "ipsec autokey-map #{@autokey_policy_map_name} #{@access_list_name} peer #{new_ip} #{@sa_proposal_name}"
    self
  end

  def global_ip
    status = exec("show tunnel status")
    status =~ /Source address is (.+)/
    unless $1.split(".").size == 4
      false
    else
      $1
    end
  end

  private
  def while_exit
    @session.cmd("") do |c|
      unless c =~ /^.+\(config\)%/
        @session.cmd("exit")
        false
      else
        true
      end
    end
  end

  def exec(str)
    ret = ""
    @session.cmd(str){|c| ret += c }
    ret
  end
end

@edge = IX2015.new do
  host "192.168.1.10"
  id "username"
  password "password"

  ike_policy_name "ike-policy"
  key "leaf-key"
  ike_proposal_name "ike-prop"

  autokey_policy_map_name "ipsec-policy"
  access_list_name "access-list"
  sa_proposal_name "ipsec-prop"
end

@center = IX2015.new do
  host "192.168.100.1"
  id "username"
  password "leaf-key"
end.login

# センターからグローバルIPを取得
unless @ip = @center.global_ip
  return
end

#トンネルが張られているかチェック
unless @center.tunnel?("1.0")
  @edge.login
  @edge.update_ip(@ip)
  @edge.logout
end

@center.logout
