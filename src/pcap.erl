%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc libpcap parsing/generating library
%% @end
%%%-------------------------------------------------------------------
-module(pcap).
-include_lib("eunit/include/eunit.hrl").
%% API
-export([]).
-compile(export_all).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
-include_lib("kernel/src/inet_dns.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include_lib("stdlib/include/ms_transform.hrl").
-define(PCAP_MAGIC, <<16#d4,16#c3,16#b2,16#a1>>).
-record(pcap_hdr, {version,tz_correction,sigfigures,snaplen,datalinktype,endianess}).
%%====================================================================
%% PCAP Header parser/generator
%%====================================================================
parse_header(<<16#d4,16#c3,16#b2,16#a1,
              VersionMajor:16/little,
              VersionMinor:16/little,
              TzCorrection:32/signed-little,
              SigFigures:32/little,
              SnapLen:32/little,
              DataLinkType:32/little,
              Rest/binary>>) ->
    {#pcap_hdr{version={VersionMajor, VersionMinor},
               tz_correction=TzCorrection,
               sigfigures=SigFigures,
               snaplen=SnapLen,
               datalinktype=DataLinkType,
               endianess=little},
     Rest};
parse_header(<<16#a1,16#b2,16#c3,16#d4,
              VersionMajor:16/big,
              VersionMinor:16/big,
              TzCorrection:32/signed-big,
              SigFigures:32/big,
              SnapLen:32/big,
              DataLinkType:32/big,
              Rest/binary>>) ->
    {#pcap_hdr{version={VersionMajor, VersionMinor},
               tz_correction=TzCorrection,
               sigfigures=SigFigures,
               snaplen=SnapLen,
               datalinktype=DataLinkType,
               endianess=big},
     Rest}.

generate_pcap_gloabl_healer_bin() ->
    to_binary(#pcap_hdr{version={2, 4},
                    tz_correction=0,
                    sigfigures=0,
                    snaplen=65535,
                    datalinktype=1,
                    endianess=little}).
to_binary(#pcap_hdr{version={VersionMajor, VersionMinor},
                    tz_correction=TzCorrection,
                    sigfigures=SigFigures,
                    snaplen=SnapLen,
                    datalinktype=DataLinkType,
                    endianess=little}) ->
    <<16#d4,16#c3,16#b2,16#a1,
     VersionMajor:16/little,
     VersionMinor:16/little,
     TzCorrection:32/signed-little,
     SigFigures:32/little,
     SnapLen:32/little,
     DataLinkType:32/little>>;
to_binary(#pcap_hdr{version={VersionMajor, VersionMinor},
                    tz_correction=TzCorrection,
                    sigfigures=SigFigures,
                    snaplen=SnapLen,
                    datalinktype=DataLinkType,
                    endianess=big}) ->
    <<16#a1,16#b2,16#c3,16#d4,
     VersionMajor:16/big,
     VersionMinor:16/big,
     TzCorrection:32/signed-big,
     SigFigures:32/big,
     SnapLen:32/big,
     DataLinkType:32/big>>.

%%====================================================================
%% PCAP packet parser/generator
%%====================================================================

parse_pcap_packet({#pcap_hdr{endianess=Endianess}, Data}) ->
    parse_pcap_packet(Endianess, Data).
parse_pcap_packet(#pcap_hdr{endianess=Endianess}, Data) ->
    parse_pcap_packet(Endianess, Data);
parse_pcap_packet(little,
             <<TS_Secs:32/little,
              TS_USecs:32/little,
              PktLen:32/little,
              OrigLen:32/little,
              Data:PktLen/binary,
              RestPacket/binary>>) ->
   Pcap = #pcap_pkt{timestamp={TS_Secs,TS_USecs},orig_len=PktLen},
  %{ProtStack,Rest} = ethernet(Data,[#pcap_pkt{timestamp={TS_Secs,TS_USecs},orig_len=PktLen}]),
  %{ProtStack,RestPacket};
    {Pcap,Data,RestPacket};
parse_pcap_packet(big,
             <<TS_Secs:32/big,
              TS_USecs:32/big,
              PktLen:32/big,
              OrigLen:32/big,
              Data:PktLen/binary,
              RestPacket/binary>>) ->
    Pcap = #pcap_pkt{timestamp={TS_Secs,TS_USecs},orig_len=PktLen},
    %{ProtStack,Rest} = ethernet(Data,[#pcap_pkt{timestamp={TS_Secs,TS_USecs},orig_len=PktLen}]),
    %{ProtStack,RestPacket}.
    {Pcap,Data,RestPacket}.

%parse_packet(_, Bin) ->
   % {no_packet, Bin}.

generate_pcap_packet_header(TS_Secs,TS_USecs,OrigLen,Data) ->
    to_binary(little,#pcap_pkt{timestamp={TS_Secs,TS_USecs},
                            orig_len=OrigLen,
                            data=Data}).
to_binary(#pcap_hdr{endianess=End}, #pcap_pkt{} = P) ->
    to_binary(End, P);
to_binary(little, #pcap_pkt{timestamp={TS_Secs,TS_USecs},
                            orig_len=OrigLen,
                            data=Data}) ->
    DataSize = byte_size(Data),
    <<TS_Secs:32/little,
     TS_USecs:32/little,
     DataSize:32/little,
     OrigLen:32/little,
     Data/binary>>;
to_binary(big, #pcap_pkt{timestamp={TS_Secs,TS_USecs},
                         orig_len=OrigLen,
                         data=Data}) ->
    DataSize = byte_size(Data),
    <<TS_Secs:32/big,
     TS_USecs:32/big,
     DataSize:32/big,
     OrigLen:32/big,
     Data/binary>>.
%%====================================================================
%% PCAP file reader/writer (small files only)
%%====================================================================
parse_file(File) ->
    io:format("File : ~p,~n",[File]),
    {ok, Bin} = file:read_file(File),
    {Header, PacketsData} = parse_header(Bin),
    bg:bmap(fun(Endianess,Data,N,Offset) ->
                {Pcap,FrameData,RestPacket} =  parse_pcap_packet(Endianess,Data),
                gtp_decode_server:decode(File,N,
                                         Offset,Pcap,
                                         FrameData),
                RestPacket
    end,Header#pcap_hdr.endianess,PacketsData,1,0).

write_file(File, {Header, Packets}) ->
    write_file(File, Header, Packets).

write_file(File, Header, Packets) ->
    {ok, Dev} = file:open(File, [write,delayed_write]),
    ok = file:write(Dev, to_binary(Header)),
    lists:foreach(fun (Pkt) ->
                          ok = file:write(Dev, to_binary(Header, Pkt))
                  end,
                  Packets),
    ok = file:close(Dev).

%%====================================================================
%% PCAP timestamp conversion functions
%%====================================================================

pcap_ts_to_gmt(#pcap_pkt{timestamp=Ts}) -> pcap_ts_to_gmt(Ts);
pcap_ts_to_gmt({UnixTS, _MicroSecs}) ->
    unix_ts_to_datetime(UnixTS).

pcap_ts_to_now(#pcap_pkt{timestamp=Ts}) -> pcap_ts_to_now(Ts);
pcap_ts_to_now({UnixTS, MicroSecs}) ->
    {UnixTS div 1000000,
     UnixTS rem 1000000,
     MicroSecs}.

pcap_ts(#pcap_pkt{timestamp=Ts}) -> Ts.

unix_ts_to_datetime(Ts) when is_list(Ts) ->
    unix_ts_to_datetime(list_to_integer(Ts));
unix_ts_to_datetime(Ts) when is_integer(Ts) ->
    Ts1970 = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    calendar:gregorian_seconds_to_datetime(Ts1970 + Ts+8*60*60).

%%====================================================================
%% Ethernet/IPv4 Packet parsers
%%====================================================================
ethernet(#pcap_pkt{data=Data},ProtStack) -> ethernet(Data,ProtStack);
ethernet(<<Src:6/binary,
          Dest:6/binary,
          16#8100:16,_:16,Type:16,
          Rest/binary>>,ProtStack) ->
   ipv4(Rest,ProtStack ++ [#ether{src=Src,dest=Dest,type=16#0800}]);
ethernet(<<Src:6/binary,
          Dest:6/binary,
          16#0800:16,
          Rest/binary>>,ProtStack) ->
    ipv4(Rest,ProtStack ++ [#ether{src=Src,dest=Dest,type=16#0800}]);
ethernet(<<Src:6/binary,
          Dest:6/binary,
          Type:16,
          Rest/binary>>,ProtStack) ->
    ipv4(Rest,ProtStack ++ [#ether{src=Src,dest=Dest,type=Type}]).
-define(IP_VERSION, 4).
-define(IP_MIN_HDR_LEN, 5).

ipv4(Dgram = <<?IP_VERSION:4, HLen:4, SrvcType:8, TotLen:16,
              ID:16, 0:1,_:1,0:1, 0:13, TTL:8, Proto:8, HdrChkSum:16,
              SrcIP:32, DestIP:32, RestDgram/binary>>,ProtStack)
  when HLen >= 5, 4*HLen =< byte_size(Dgram) ->
    OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
    <<Opts:OptsLen/binary, DgramPayload/binary>> = RestDgram,
    IP_Packet = #ip_packet{src=SrcIP, dst=DestIP,totLen=TotLen,proto=Proto},
    udp_tcp_parse(IP_Packet#ip_packet.proto,DgramPayload,ProtStack ++ [IP_Packet]);
ipv4(Dgram = <<?IP_VERSION:4, HLen:4, SrvcType:8, TotLen:16,
              ID:16, _:1,_:1,1:1, Offset:13, TTL:8, Proto:8, HdrChkSum:16,
              SrcIP:32, DestIP:32, RestDgram/binary>>,ProtStack)
  when HLen >= 5, 4*HLen =< byte_size(Dgram) ->
    OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
    <<Opts:OptsLen/binary, DgramPayload/binary>> = RestDgram,
    IP_Packet = #ip_packet{src=SrcIP, dst=DestIP,totLen=TotLen,proto=Proto},
    ets:insert(ip_fragments_table,{erlang:now(),ID,SrcIP,DestIP,Offset*8,byte_size(DgramPayload),DgramPayload,1}),
    {ProtStack,DgramPayload};
ipv4(Dgram = <<?IP_VERSION:4, HLen:4, SrvcType:8, TotLen:16,
              ID:16, _:1,_:1,0:1, Offset:13, TTL:8, Proto:8, HdrChkSum:16,
              SrcIP:32, DestIP:32, RestDgram/binary>>,ProtStack)
  when HLen >= 5, 4*HLen =< byte_size(Dgram) ->
    OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
    <<Opts:OptsLen/binary, DgramPayload/binary>> = RestDgram,
    IP_Packet = #ip_packet{src=SrcIP, dst=DestIP,totLen=TotLen,proto=Proto},
    %
    RRRR = find_ip_fragments(SrcIP,DestIP,ID),
    RealOffset = Offset * 8,
    case RRRR of
        [] -> {ProtStack,DgramPayload};
        _  ->       
            All_DgramPayload = [{erlang:now(),ID,SrcIP,DestIP,Offset*8,byte_size(DgramPayload),DgramPayload,0}|RRRR],
            Complated = check_dataPlayLoad(All_DgramPayload),
            case Complated of
                {false,_} -> {ProtStack,DgramPayload};
                {true,Data} ->
                    Data1 = list_to_binary(lists:reverse(Data)),                    
                    F = ets:fun2ms(fun({R_Time,R_ID,R_SrcIP,R_DestIP,R_Offset,R_Len,R_DgramPayload,MoreSet}) when R_SrcIP =:=SrcIP,
                                   R_DestIP =:= DestIP,R_ID =:=  ID -> true
                    end),
                    ets:select_delete(ip_fragments_table,F),
                    udp_tcp_parse(IP_Packet#ip_packet.proto,Data1,ProtStack ++ [IP_Packet])
            end           
    end;
ipv4(Rest,ProtStack) -> {ProtStack,Rest}.

check_dataPlayLoad(All_DgramPayload) ->
    check_dgramPayload3(0,All_DgramPayload,[]).

check_dgramPayload3(StartOffset,[],_Data)  ->
    {false,_Data};
check_dgramPayload3(StartOffset,IpDataS,Data) ->
        OffsetList = [{R_Time,R_ID,R_SrcIP,R_DestIP,R_Offset,R_Len,R_DgramPayload,MoreSet}
                        ||{R_Time,R_ID,R_SrcIP,R_DestIP,R_Offset,R_Len,R_DgramPayload,MoreSet}  <-  IpDataS,R_Offset =:= StartOffset],
        case OffsetList of
            [] -> {false,Data};
            [{R_Time,R_ID,R_SrcIP,R_DestIP,R_Offset,R_Len,R_DgramPayload,MoreSet}|T]   ->
                case MoreSet of
                       0 -> {true,[R_DgramPayload|Data]};
                       _ -> 
                           check_dgramPayload3(R_Offset+R_Len,IpDataS,[R_DgramPayload|Data])
                end
        end.

find_ip_fragments(SrcIp_A,DestIp_A,ID_A) ->
    F = fun() ->
        qlc:q([{Time,ID,SrcIP,DestIP,Offset,Len,DgramPayload,MoreSet}
               || {Time,ID,SrcIP,DestIP,Offset,Len,DgramPayload,MoreSet} <- ets:table(ip_fragments_table),SrcIP =:=SrcIp_A,DestIP =:= DestIp_A,ID =:=  ID_A])
    end,
    Q = F(),
    Result = qlc:e(Q).

%%Transport_Layer_dissector
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%解析udp或者tcp协议
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
udp_tcp_parse(16#11,<<SrcPrt:16, DstPrt:16, Length:16, Checksum:16, Payload/binary>>,ProtStack) ->
    Udp_tcp_packet = #udp_tcp_packet{src_port=SrcPrt, dst_port=DstPrt,message_type=16#11},
    app_prot_parse(Udp_tcp_packet,ProtStack ++ [Udp_tcp_packet],Payload);
udp_tcp_parse(16#06,<<SrcPrt:16, DstPrt:16, Seq_num:32, Ack_num:32, DataOffset:4,Reserved:6,Control:6,
     Window:16,Checksum:16,UrgentPointer:16,Payload/binary>>,ProtStack) ->
     Udp_tcp_packet =  #udp_tcp_packet{src_port=SrcPrt, dst_port=DstPrt,message_type=16#06},
     app_prot_parse(Udp_tcp_packet,ProtStack ++ [Udp_tcp_packet],Payload);
 udp_tcp_parse(16#84,<<SrcPrt:16, DstPrt:16, Vtag:32, Checksum:32, DataOffset:4,Reserved:6,Control:6,
     Window:16,UrgentPointer:16,Payload/binary>>,ProtStack) ->
     Udp_tcp_packet =  #udp_tcp_packet{src_port=SrcPrt, dst_port=DstPrt,message_type=16#06},
     app_prot_parse(Udp_tcp_packet,ProtStack ++ [Udp_tcp_packet],Payload);
udp_tcp_parse(_,Rest,ProtStack) ->
    {ProtStack,Rest}.

%%解析基于tcp协议之上的应用层协议%%http 协议
app_prot_parse(#udp_tcp_packet{src_port=80, dst_port=DstPrt,message_type=16#06}=Packet,ProtStack,Payload)->
 case erlang:decode_packet(http,Payload,[]) of
     {ok,HttpHeader,Rest} ->
         {ProtStack ++ [HttpHeader],Rest};
     R -> {ProtStack,Payload}
 end;
app_prot_parse(#udp_tcp_packet{src_port=SrcPrt, dst_port=80}=Packet,ProtStack,Payload)->
 case erlang:decode_packet(http,Payload,[]) of
     {ok,HttpHeader,Rest} ->
         
         {ProtStack ++ [HttpHeader],Rest};
     R                              ->
         {ProtStack,Payload}
 end;
%%解析基于udp协议之上的应用层协议(gtp协议)
app_prot_parse( #udp_tcp_packet{src_port=SrcPrt,dst_port=2152,message_type=16#11}=Packet,ProtStack,Payload) ->
    gtp(#udp_tcp_packet{src_port=SrcPrt,dst_port=2152,message_type=16#11}=Packet,ProtStack,Payload);
app_prot_parse( #udp_tcp_packet{src_port=2152,dst_port=DestPrt,message_type=16#11}=Packet,ProtStack,Payload) ->
    gtp(#udp_tcp_packet{src_port=2152,dst_port=DestPrt,message_type=16#11}=Packet,ProtStack,Payload);
app_prot_parse( #udp_tcp_packet{src_port=SrcPrt,dst_port=2123,message_type=16#11}=Packet,ProtStack,Payload) ->
    gtp(#udp_tcp_packet{src_port=SrcPrt,dst_port=2123,message_type=16#11}=Packet,ProtStack,Payload);
app_prot_parse( #udp_tcp_packet{src_port=2123,dst_port=DestPrt,message_type=16#11}=Packet,ProtStack,Payload) ->
    gtp(#udp_tcp_packet{src_port=2123,dst_port=DestPrt,message_type=16#11}=Packet,ProtStack,Payload);
app_prot_parse( #udp_tcp_packet{src_port=SrcPrt,dst_port=3386,message_type=16#11}=Packet,ProtStack,Payload) ->
    gtp(#udp_tcp_packet{src_port=SrcPrt,dst_port=3386,message_type=16#11}=Packet,ProtStack,Payload);
app_prot_parse( #udp_tcp_packet{src_port=3386,dst_port=DestPrt,message_type=16#11}=Packet,ProtStack,Payload) ->
    gtp(#udp_tcp_packet{src_port=3386,dst_port=DestPrt,message_type=16#11}=Packet,ProtStack,Payload);
%%解析基于udp协议之上的应用层协议(dns协议)
app_prot_parse( #udp_tcp_packet{src_port=SrcPrt,dst_port=53,message_type=Message_type}=Packet,ProtStack,Payload) ->
    case inet_dns1:decode(Payload) of
            {ok,DnsRec} ->      {ProtStack ++ [DnsRec],<<>>};
            {error,Reason} -> {ProtStack,Payload}
    end;
app_prot_parse( #udp_tcp_packet{src_port=53,dst_port=DstPrt,message_type=Message_type}=Packet,ProtStack,Payload) ->
    case inet_dns1:decode(Payload) of
            {ok,DnsRec} ->      {ProtStack ++ [DnsRec],<<>>};
            {error,Reason} -> {ProtStack,Payload}
    end;

app_prot_parse(_Packet,_ProtStack,_Payload)->
 {_ProtStack,_Payload}.


gtp(#udp_tcp_packet{src_port=SrcPrt,dst_port=DestPrt,message_type=16#11}=Packet,ProtStack,Payload) ->
    %io:format("current protstack ~p ~n",[ProtStack]),
    case gtpp_decode:decode_message(Payload) of
        {not_support_gtp_version,_}   ->
            {ProtStack,Payload};
        {GtpH,GtpIES,Rest} ->
            Gtp = {GtpH,GtpIES},
            {P,R} = case GtpH#gtpp_header.msg_type of
                        gtp_msg_tpdu ->
                             %TotalLen = ( hd(ProtStack))#pcap_pkt.orig_len,
                            %io:format(" ~p,~p,~p ~n",[TotalLen,byte_size(Rest),SSS]),
                            ipv4(Rest,ProtStack ++ [Gtp]);
                        _ ->
                            {ProtStack ++ [Gtp],Rest}
            end,
            {P,R}
    end.
%%====================================================================
%% Internal functions
%%====================================================================
magic() ->
    <<16#a1, 16#b2, 16#c3, 16#d4>>.
magic(big) ->
    <<N:32/big>> = magic(), N;
magic(little) ->
    <<N:32/little>> = magic(), N.    

time_filter(Times) when is_list(Times) ->
    TenMins = 60 * 10,
    Ts1970 = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    TsTimes = [calendar:datetime_to_gregorian_seconds(hd(calendar:local_time_to_universal_time_dst(Time))) - Ts1970
               || Time <- Times],
    fun (Bin, {Hdr,Acc}) ->
            case parse_pcap_packet(Hdr,Bin) of
                {Pkt = #pcap_pkt{timestamp=Ts}, Rest} ->
                    case [TsTime || TsTime <- TsTimes,
                                    abs(Ts - TsTime) =< TenMins] of
                        [] -> Rest;
                        _ -> {{Hdr, [Pkt|Acc]}, Rest}
                    end;
                {no_packet, Rest} ->
                    Rest
            end
    end.

iterator(Bin, init) ->
    {Hdr, Rest} = parse_header(Bin),
    {more, {Hdr, []}, Rest};
iterator(Bin, {Hdr, Pkts}) ->
    case parse_pcap_packet(Hdr, Bin) of
        {no_packet, Rest} ->
            {incomplete, {Hdr, Pkts}, Rest};
        {Pkt, Rest} ->
            {more, {Hdr, [Pkt|Pkts]}, Rest}
    end.

filterator(Bin, {init,F}) ->
    {Hdr, Rest} = parse_header(Bin),
    {more, {Hdr, F, []}, Rest};
filterator(Bin, {Hdr, F, Pkts}) ->
    case parse_pcap_packet(Hdr, Bin) of
        {no_packet, Rest} ->
            {incomplete, {Hdr, F, Pkts}, Rest};
        {Pkt, Rest} ->
            case F(Pkt) of
                true ->
                    {more, {Hdr, F, [Pkt|Pkts]}, Rest};
                false ->
                    {more, {Hdr, F, Pkts}, Rest}
            end
    end.

count(Bin, {init,F}) ->
    {Hdr, Rest} = parse_header(Bin),
    {more, {Hdr, F, 0}, Rest};
count(Bin, {Hdr, F, Count}) ->
    case parse_pcap_packet(Hdr, Bin) of
        {no_packet, Rest} ->
            {incomplete, {Hdr, F, Count}, Rest};
        {Pkt, Rest} ->
            case F(Pkt) of
                true ->
                    {more, {Hdr, F, Count+1}, Rest};
                false ->
                    {more, {Hdr, F, Count}, Rest}
            end
    end.

file_writer(Bin, {init, F, File}) ->
    {ok, Dev} = file:open(File, [write, raw, binary, delayed_write]),
    {Hdr, Rest} = parse_header(Bin),
    ok = file:write(Dev, to_binary(Hdr)),
    {more, {Hdr, F, Dev}, Rest};
file_writer(Bin, {Hdr, F, Dev}) ->
    case parse_pcap_packet(Hdr, Bin) of
        {no_packet, Rest} ->
            {incomplete, {Hdr, F, Dev}, Rest};
        {Pkt, Rest} ->
            case F(Pkt) of
                true ->
                    ok = file:write(Dev, to_binary(Hdr, Pkt)),
                    {more, {Hdr, F, Dev}, Rest};
                false ->
                    {more, {Hdr, F, Dev}, Rest}
            end
    end.
  

outage_window_filter(Times) ->
    Ts1970 = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    TsTimes = [calendar:datetime_to_gregorian_seconds(hd(calendar:local_time_to_universal_time_dst(Time))) - Ts1970
               || Time <- Times],
    TenMins = 60 * 10,
    fun (#pcap_pkt{timestamp={Ts,_}}) ->
            lists:any(fun (T) -> abs(T - Ts) =< TenMins end,
                      TsTimes)
    end.

filter_test() ->
    UnixTS = 1187577884,
    Pkt = #pcap_pkt{timestamp={1187577884,0}},
    F = outage_window_filter([calendar:universal_time_to_local_time(pcap:unix_ts_to_datetime(1187577884))]),
    ?assertMatch(true, F(Pkt)).
