-module(udp_tcp).
-export([parse/3]).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
parse(16#11,<<SrcPrt:16, DstPrt:16, Length:16, Checksum:16, Payload/binary>>,ProtStack) ->
    {ProtStack ++ [#udp_tcp_packet{src_port=SrcPrt, dst_port=DstPrt,message_type=16#11}],Payload};
parse(16#06,<<SrcPrt:16, DstPrt:16, Seq_num:32, Ack_num:32, DataOffset:4,Reserved:6,Control:6,
      Window:16,Checksum:16,UrgentPointer:16,Payload/binary>>,ProtStack) ->
    {ProtStack ++ [#udp_tcp_packet{src_port=SrcPrt, dst_port=DstPrt,message_type=16#06}],Payload}.

parse_bootp(Message) ->
	<<HwType,AddrLength,Hops,TransactionID:32,Elapsed:16,BootpFlags:16, 
	  ClientIP:4/binary,YourClientIP:4/binary,NextServerIP:4/binary,
	  RelayAgentIP:4/binary,ClientMAC:6/binary,DHCPServerName:64/binary, BootFile:128/binary,
	  _Pad:10/binary, Cookie:32, Options/binary>> = Message,	
	#bootp_packet{
		hw_type = HwType, addr_length = AddrLength, hops = Hops, transaction_id = TransactionID, 
		elapsed = Elapsed, bootp_flags = BootpFlags, client_ip = util:extract_ip(ClientIP), 
		your_client_ip = util:extract_ip(YourClientIP), next_server_ip = util:extract_ip(NextServerIP), 
		relay_agent_ip = util:extract_ip(RelayAgentIP), client_mac = util:extract_mac(ClientMAC), 
		dhcp_server_name = binary_to_list(DHCPServerName), boot_file = binary_to_list(BootFile), 
		cookie = Cookie, options = listify_bootp_options(Options)
	}.

listify_bootp_options(Data) ->
	case Data of
		<<255>> -> [];
		Data -> 
			if size(Data) > 0 ->
				<<Type, Length, Rest/binary>> = Data,
				<<Value:Length/binary, Next/binary>> = Rest,
				[ #bootp_option{ type = Type, value = binary_to_list(Value) } ] ++ listify_bootp_options(Next)
			end
	end.

