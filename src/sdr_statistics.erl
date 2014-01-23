-module(sdr_statistics).
%%%-------------------------------------------------------------------
%%% File    : sdr_statistics.erl
%%% Author  : kebo <huang.kebo@gmail.com>
%%% Description :gtp协议分析处理server
%%% 接受来自gtp_decode_server解析后的数据做关联,统计
%%% Created :  2 Mar 2009 by my name <huang.kebo@gmail.com>
%%%-------------------------------------------------------------------
-behaviour(gen_server).
%% API
-export([start_link/0]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-export([message/1]).
-export([do_clean/1]).
-export([gtp_message1/4]).
-record(state, {pdp_table,stat_pdp_connect_t,pdp_conn_ct,stat_session_info_t,
                delete_pdp_table,update_pdp_table}).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include_lib("kernel/src/inet_dns.hrl").
-include("../include/radius.hrl").
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link() ->
    io:format("gtp_sdr_statistics starting......~n"),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Pdp_Table = ets:new(pdp_table, [public,set,named_table ,{write_concurrency, true}]),
    Delete_Table = ets:new(delete_pdp_table, [public,bag,named_table ,{write_concurrency, true}]),
    Update_Table = ets:new(update_pdp_table, [public,bag,named_table ,{write_concurrency, true}]),
    %Stat_pdp_conn_t = ets:new(stat_pdp_connect_table, named_table ,[public,bag, {write_concurrency, true}]),
    Stat_session_info_t = ets:new(stat_session_info_t, [public,bag,named_table ,{write_concurrency, true}]),
    {ok, #state{}}.

do_clean(ExpiredTime) ->
    gen_server:call(?MODULE,{clean,ExpiredTime}).

gtp_message1(File,Offset,Num,Len) ->
    {db, 'dsm_packet_node@localhost'}!{Num,Offset,Len,File},
    ok.
%%----------------------------------------------------------------------------------------------------------
message([Filename,Offset,Num,Pcap_pkt,ProtStack]) when length(ProtStack) > 3  ->
    process_message([Filename,Offset,Num,pcap:pcap_ts(Pcap_pkt),ProtStack],lists:nth(4,ProtStack));
message([Filename,Offset,Num,Pcap_pkt,ProtStack]) ->
    ok.
%%-----------------------------------------------------------------------------------------------------------
process_message([Filename,Offset,Num,Time,ProtStack],App) when is_record(App,rad_pdu)  ->
    radius_sdr_statics:process_message([Filename,Offset,Num,Time,ProtStack],App);
process_message([Filename,Offset,Num,Time,ProtStack],App) when is_record(App,dns_rec) ->
    dns_sdr_statistics:process_message([Filename,Offset,Num,Time,ProtStack],App);
process_message([Filename,Offset,Num,Time,ProtStack],App) ->
    EthernetHeader =  lists:nth(1,ProtStack),
    IpHeader =  lists:nth(2,ProtStack),
    UdpHeader = lists:nth(3,ProtStack),
    {GtpHeader,GtpIES} = lists:nth(4,ProtStack),    
    case GtpHeader#gtpp_header.msg_type of
        create_pdp_context_request ->
            create_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES);
        create_pdp_context_response ->
            create_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES);
        delete_pdp_context_request ->
            delete_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES);
        delete_pdp_context_response ->
            delete_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES);
        update_pdp_context_Request ->
            update_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES);
        update_pdp_context_response ->
            update_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES);
%        gtp_msg_tpdu ->
%            gtp_msg_tpdu(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,lists:nthtail(4,ProtStack));
        _ ->
            ok
    end;
process_message(_,App)->
    ok.
%%====================================================================
%% API
%%====================================================================
%%创建pdp上下文
create_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    ets:insert(pdp_table,
               {
                   {  GtpHeader#gtpp_header.seqnum,
                    IpHeader#ip_packet.src,
                    IpHeader#ip_packet.dst,
                    find_teid_from_ies(GtpIES)},
                        {  Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num}
               }).

create_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    Pdp_create_request = ets:lookup(pdp_table,
                                    {  GtpHeader#gtpp_header.seqnum,
                                     IpHeader#ip_packet.dst,
                                     IpHeader#ip_packet.src,
                                     GtpHeader#gtpp_header.teid
                                    }),
    case Pdp_create_request of
        [] ->
            ok;
        [{{SeqNo,Req_src_ip,Req_dest_ip,Teid_c},{Req_Time,_Req_EthernetHeader,Req_IpHeader,Req_UdpHeader,
                                                 Req_GtpHeader,Req_GtpIES,Req_Filename,Req_Offset,Req_Num}}|T] ->
            ets:delete(pdp_table,{SeqNo,Req_src_ip,Req_dest_ip}),%%
            insert_stat_session_info(Req_Time,Time,Req_IpHeader,Req_GtpHeader,Req_GtpIES,IpHeader,GtpHeader,GtpIES),
            {db, 'dsm_oracle_node@localhost'} !
                {"create",Req_Time,Time,GtpHeader#gtpp_header.seqnum,util:i_to_ip(Req_src_ip),
                 Req_UdpHeader#udp_tcp_packet.src_port,util:i_to_ip(Req_dest_ip),
                 Req_UdpHeader#udp_tcp_packet.dst_port,
                 find_cause_from_ies(GtpIES),
                 find_apn_from_ies(Req_GtpIES),
                 find_msisdn_from_ies(Req_GtpIES),
                 find_end_user_addr_from_req_resp(Req_GtpIES,GtpIES),
                 Req_Num,Num,Req_Filename,Req_Offset,
                 Filename,Offset,
                 find_teid_from_ies(GtpIES),
                 find_teid_from_ies(Req_GtpIES),
                 find_teid_i_from_ies(GtpIES),
                 find_teid_i_from_ies(Req_GtpIES)}
    end.
%%更新pdp上下文
update_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    UpdateTable  = update_pdp_table,
    SessionTable  = stat_session_info_t,
    Teid_c_up  = GtpHeader#gtpp_header.teid,
    F = fun(I) ->
            qlc:q([{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                    End_time,Upload,Download,Session_duration,Apn}
                   || {Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                       End_time,Upload,Download,Session_duration,Apn}
                   <-  ets:table(SessionTable),
                   Teid_c_up  =:= I
                  ])
        end,
    Q = F(Teid_c_up),
    Session_result  =  qlc:e(Q),
    case Session_result  of
        [] -> ok; %%需要处理会话信息
        [{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
          End_time,Upload,Download,Session_duration,Apn}|T] ->
                  %%%%%-------------查询相关的update response数据
            F1  = fun(I,ReqIpHeader,ReqGtpHeader) ->
                    qlc:q([{RespTime,RespEthernetHeader,RespIpHeader,
                            RespUdpHeader,RespGtpHeader,RespGtpIES,
                            RespFilename,RespOffset,RespNum}
                           || {RespTime,RespEthernetHeader,RespIpHeader,
                               RespUdpHeader,RespGtpHeader,RespGtpIES,
                               RespFilename,RespOffset,RespNum}
                           <- ets:table(UpdateTable),
                           RespGtpHeader#gtpp_header.teid =:= I,
                           RespGtpHeader #gtpp_header.seqnum  =:=  ReqGtpHeader #gtpp_header.seqnum,
                           RespIpHeader#ip_packet.dst =:= ReqIpHeader#ip_packet.src ,
                           RespIpHeader#ip_packet.src =:= ReqIpHeader#ip_packet.dst
                          ])
                  end,
            AQ  = F1(Teid_c_down,IpHeader,GtpHeader),
            Update_pdp_result  =  qlc:e(AQ),
            case Update_pdp_result  of
                [] -> ets:insert(update_pdp_table,{Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num});
                [{RespTime,RespEthernetHeader,RespIpHeader,
                  RespUdpHeader,RespGtpHeader,RespGtpIES,RespFilename,
                  RespOffset,RespNum}|T1]  ->
                    Teid_c_up = GtpHeader#gtpp_header.teid,
                    Teid_c_down =  RespGtpHeader#gtpp_header.teid,
                    New_teid_c_up = find_teid_from_ies(GtpIES) ,
                    New_teid_c_down = find_teid_from_ies(RespGtpIES) ,
                    New_teid_u_up = find_teid_i_from_ies(RespGtpIES),
                    New_teid_u_down = find_teid_i_from_ies(GtpIES),
                    case New_teid_c_up of
                        "" -> New_teid_c_up1 = GtpHeader#gtpp_header.teid;
                        _ -> New_teid_c_up1 = New_teid_c_up
                    end,
                    ets:delete_object(update_pdp_table,{RespTime,RespEthernetHeader,RespIpHeader,RespUdpHeader,
                                                        RespGtpHeader,RespGtpIES,RespFilename,RespOffset,RespNum}),
                    {db, 'dsm_oracle_node@localhost'} !
                        {"update",Num,Offset,Filename,Time,RespNum,RespOffset,
                         RespFilename,RespTime,
                         GtpHeader#gtpp_header.seqnum,util:i_to_ip(IpHeader#ip_packet.src),
                         UdpHeader#udp_tcp_packet.src_port,util:i_to_ip(IpHeader#ip_packet.dst),
                         UdpHeader#udp_tcp_packet.dst_port,
                         find_cause_from_ies(RespGtpIES),
                         GtpHeader#gtpp_header.teid,
                         RespGtpHeader#gtpp_header.teid,
                         Msisdn,
                         New_teid_c_up1,
                         New_teid_c_down,
                         New_teid_u_up,
                         New_teid_u_down},
                    update_session_teid(Teid_c_up,Teid_c_down,Msisdn,
                                        New_teid_c_up1,New_teid_c_down,New_teid_u_up,
                                        New_teid_u_down)
            end
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
update_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    UpdateTable  = update_pdp_table,
    SessionTable  = stat_session_info_t,
    Teid_c_down  = GtpHeader#gtpp_header.teid,
    F = fun(I) ->
            qlc:q([{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                    End_time,Upload,Download,Session_duration,Apn}
                   ||
                       {Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                        End_time,Upload,Download,Session_duration,Apn}
                   <-  ets:table(SessionTable),
                   Teid_c_down  =:= I
                  ])
        end,
    Q = F(Teid_c_down),
    Session_result  =  qlc:e(Q),
    case Session_result  of
        [] ->  ok;
        [{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
          End_time,Upload,Download,Session_duration,Apn}|T]  ->
               %%----------------查询相关的request
            F1  = fun(I,RespIpHeader,RespGtpHeader) ->
                    qlc:q([{ReqTime,ReqEthernetHeader,
                            ReqIpHeader,ReqUdpHeader,ReqGtpHeader,
                            ReqGtpIES,ReqFilename,ReqOffset,ReqNum}
                           || {ReqTime,ReqEthernetHeader,ReqIpHeader,
                               ReqUdpHeader,ReqGtpHeader,ReqGtpIES,
                               ReqFilename,ReqOffset,ReqNum}
                           <- ets:table(UpdateTable),
                           ReqGtpHeader#gtpp_header.teid    =:=  I,
                           ReqGtpHeader#gtpp_header.seqnum  =:= RespGtpHeader #gtpp_header.seqnum,
                           ReqIpHeader#ip_packet.src  =:= RespIpHeader#ip_packet.dst,
                           ReqIpHeader#ip_packet.dst =:= RespIpHeader#ip_packet.src
                          ])
                  end,
            AQ  = F1(Teid_c_up,IpHeader,GtpHeader),
            Update_pdp_result  =  qlc:e(AQ),
            case Update_pdp_result of
                [] ->  ets:insert(update_pdp_table,{Time,EthernetHeader,
                                                    IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num});
                [{ReqTime,ReqEthernetHeader,ReqIpHeader,
                  ReqUdpHeader,ReqGtpHeader,ReqGtpIES,
                  ReqFilename,ReqOffset,ReqNum}|T1] ->
                    Teid_c_up = ReqGtpHeader#gtpp_header.teid,
                    Teid_c_down =  GtpHeader#gtpp_header.teid,
                    New_teid_c_up = find_teid_from_ies(ReqGtpIES) ,
                    New_teid_c_down = find_teid_from_ies(GtpIES) ,
                    New_teid_u_up = find_teid_i_from_ies(ReqGtpIES),
                    New_teid_u_down = find_teid_i_from_ies(GtpIES),
                    case New_teid_c_up of
                        "" -> New_teid_c_up1 = ReqGtpHeader#gtpp_header.teid;
                        _ -> New_teid_c_up1 = New_teid_c_up
                    end,
                    ets:delete_object(update_pdp_table,
                                      {ReqTime,ReqEthernetHeader,ReqIpHeader,ReqUdpHeader,
                                       ReqGtpHeader,ReqGtpIES,ReqFilename,ReqOffset,ReqNum}),
                    {db, 'dsm_oracle_node@localhost'} !
                        {"update",Num,Offset,Filename,Time,ReqNum,ReqOffset,
                         ReqFilename,ReqTime,
                         GtpHeader#gtpp_header.seqnum,util:i_to_ip(ReqIpHeader#ip_packet.src),
                         ReqUdpHeader#udp_tcp_packet.src_port,util:i_to_ip(ReqIpHeader#ip_packet.dst),
                         ReqUdpHeader#udp_tcp_packet.dst_port,
                         find_cause_from_ies(GtpIES),
                         Teid_c_up,
                         Teid_c_down,
                         Msisdn,
                         New_teid_c_up1,
                         New_teid_c_down,
                         New_teid_u_up,
                         New_teid_u_down
                        },
                    update_session_teid(Teid_c_up,Teid_c_down, Msisdn,
                                        New_teid_c_up1,New_teid_c_down,New_teid_u_up,
                                        New_teid_u_down)
            end               
    end.
%%delete pdp上下文
delete_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    ets:insert(delete_pdp_table,
               {Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num}).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
delete_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    %%把会话统计信息插入到库中去
    DeleteTable  = delete_pdp_table,
    SessionTable  = stat_session_info_t,
    Teid_c_down  = GtpHeader#gtpp_header.teid,
    F = fun(I) ->
            qlc:q([{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                    End_time,Upload,Download,Session_duration,Apn}
                   || {Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                       End_time,Upload,Download,Session_duration,Apn}
                   <-  ets:table(SessionTable),
                   Teid_c_down  =:= I
                  ])
        end,
    Q = F(Teid_c_down),
    Session_result  =  qlc:e(Q),
    case Session_result of
        [] -> ok;
        [{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
          End_time,Upload,Download,Session_duration,Apn} |T] ->
             %%查询delete request信息
            F1 = fun(I,RespIpHeader,RespGtpHeader) ->
                    qlc:q([{ReqTime,ReqEthernetHeader,
                            ReqIpHeader,ReqUdpHeader,
                            ReqGtpHeader,ReqGtpIES,ReqFilename,ReqOffset,ReqNum}
                           || {ReqTime,ReqEthernetHeader,
                               ReqIpHeader,ReqUdpHeader,ReqGtpHeader,
                               ReqGtpIES,ReqFilename,ReqOffset,ReqNum}
                           <- ets:table(DeleteTable),
                           ReqGtpHeader#gtpp_header.teid =:=  I,
                           ReqGtpHeader#gtpp_header.seqnum  =:= RespGtpHeader #gtpp_header.seqnum,
                           ReqIpHeader#ip_packet.src  =:= RespIpHeader#ip_packet.dst,
                           ReqIpHeader#ip_packet.dst =:= RespIpHeader#ip_packet.src
                          ])
                 end,
            AQ = F1(Teid_c_up,IpHeader,GtpHeader),
            Delete_PDP_result  =  qlc:e(AQ),
            case Delete_PDP_result of
                [] -> ok;
                [{ReqTime,ReqEthernetHeader,
                  ReqIpHeader,ReqUdpHeader,
                  ReqGtpHeader,ReqGtpIES,ReqFilename,ReqOffset,ReqNum}|T1] ->
                    ets:delete_object(delete_pdp_table,{ReqTime,ReqEthernetHeader,ReqIpHeader,ReqUdpHeader,ReqGtpHeader,
                                                        ReqGtpIES,ReqFilename,ReqOffset,ReqNum}),
                    {Begin_ts,Begin_us} = Begin_time,
                    {End_ts,End_us} = Time,
                    Se_du = ((End_ts*1000000+End_us) - (Begin_ts*1000000+Begin_us))/1000000,
                    {db, 'dsm_session_statistics_node@localhost'}!{Msisdn,
                                                                   Teid_c_up,Teid_c_down,Teid_u_up,
                                                                   Teid_u_down,Enduseraddr,Begin_time,Time,
                                                                   Upload,Download,Se_du,Apn},
                    ets:delete_object(SessionTable,{Msisdn,Teid_c_up,Teid_c_down,
                                                    Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                                                    Time,Upload,Download,Se_du,Apn}),
                    {db, 'dsm_oracle_node@localhost'} !
                        {"delete",ReqNum,ReqOffset,ReqFilename,ReqTime,Num,Offset,Filename,Time,
                         GtpHeader#gtpp_header.seqnum,
                         util:i_to_ip(ReqIpHeader#ip_packet.src ),
                         ReqUdpHeader#udp_tcp_packet.src_port,
                         util:i_to_ip(ReqIpHeader#ip_packet.dst),
                         ReqUdpHeader#udp_tcp_packet.dst_port,
                         find_cause_from_ies(GtpIES),
                         Msisdn,ReqGtpHeader#gtpp_header.teid,GtpHeader#gtpp_header.teid}
            end
    end.

gtp_msg_tpdu(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo) ->
    gen_server:call(?MODULE, {gtp_msg_tpdu,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo]}).

%gtp_msg_tpdu(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo) ->
%    if
%        length(Pdu_packInfo) >  1  ->
%            %
%            IpHeader_Pdu =  lists:nth(1,Pdu_packInfo),
%            IpHeader_UDP_TCP = lists:nth(2,Pdu_packInfo),
%            update_stat_session_info(Time,Pdu_packInfo,GtpHeader),
%            {db, 'dsm_oracle_pdu_node@localhost'}!
%                {Time,util:i_to_ip(IpHeader_Pdu#ip_packet.src),IpHeader_UDP_TCP#udp_tcp_packet.src_port,
%                 util:i_to_ip(IpHeader_Pdu#ip_packet.dst),IpHeader_UDP_TCP#udp_tcp_packet.dst_port,
%                 GtpHeader#gtpp_header.seqnum,GtpHeader#gtpp_header.msg_len,Filename,Offset,Num,GtpHeader#gtpp_header.teid};
%        true -> ok
%    end.


%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: 处理创建请求,
%% 在ets中插入一条记录等待后续会话到来。
%% 并统计一分钟内pdp创建数量
%%-------------------------------------------------------------------
handle_call({gtp_msg_tpdu,[Filename,Offset,Num,Time,_EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo]}, _From, State) ->
    if
        length(Pdu_packInfo) >  1  ->
            %
            IpHeader_Pdu =  lists:nth(1,Pdu_packInfo),
            IpHeader_UDP_TCP = lists:nth(2,Pdu_packInfo),
            update_stat_session_info(Time,Pdu_packInfo,GtpHeader),
            {db, 'dsm_oracle_pdu_node@localhost'}!
                {Time,util:i_to_ip(IpHeader_Pdu#ip_packet.src),IpHeader_UDP_TCP#udp_tcp_packet.src_port,
                 util:i_to_ip(IpHeader_Pdu#ip_packet.dst),IpHeader_UDP_TCP#udp_tcp_packet.dst_port,
                 GtpHeader#gtpp_header.seqnum,GtpHeader#gtpp_header.msg_len,Filename,Offset,Num,GtpHeader#gtpp_header.teid};
        true -> ok
    end,
    {reply, ok, State};

handle_call({clean,ExpiredTime}, _From, State) ->    
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


find_teid_from_ies([]) ->
    "0";
find_teid_from_ies([H|T]) ->
    case H of
        {teid_cp,TEID} ->
            TEID;
        _ ->
            find_teid_from_ies(T)
    end.

find_teid_i_from_ies([]) ->
    "0";
find_teid_i_from_ies([H|T]) ->
    case H of
        {teid_data_i,TEID_I} ->
            TEID_I;
        _ ->
            find_teid_i_from_ies(T)
    end.

find_apn_from_ies([]) ->
    "decodeerror";
find_apn_from_ies([H|T]) ->
    case H of
        {apn,Apn} ->
            Apn;
        _ ->
            find_apn_from_ies(T)
    end.

find_cause_from_ies([]) ->
    "version_not_support";
find_cause_from_ies([H|T]) ->
    case H of
        {cause, _, Value} ->
            Value;
        _ ->
            find_cause_from_ies(T)
    end.

find_pdp_response_ies([]) ->
    {cause, reject, 0};%%not find response cause default reject....
find_pdp_response_ies([H|T]) ->
    case H of
        {cause, accept, Value} ->
            {cause,accept, Value};
        {cause, _, Value} ->{cause, reject, Value};
        _ ->%%not match find continue.....
            find_pdp_response_ies(T)
    end.

find_msisdn_from_ies([]) ->
    {cause, reject, 0};%%not find response cause default reject....
find_msisdn_from_ies([H|T]) ->
    case H of
        {msisdn,MSISDNStr} ->
            binary_to_list(MSISDNStr);
        _ ->%%not match find continue.....
            find_msisdn_from_ies(T)
    end.


find_end_user_addr_from_req_resp(Resp,Req) ->
    case find_end_user_addr_from_ies(Resp) of
        "0.0.0.0" ->
            find_end_user_addr_from_ies(Req);
        Name ->
            Name
    end.

find_end_user_addr_from_ies([]) ->
    "0.0.0.0";
find_end_user_addr_from_ies([H|T]) ->
    case H of
        {user_addr,ipv4,Addr} ->
            binary_to_list(Addr);
        _ ->%%not match find continue.....
            find_end_user_addr_from_ies(T)
    end.
%%=========================================================
%%当收到一个pdp创建信息的时候，在表中插入一条会话的开始信息
%%包括msisdn，teid/tid,enduseraddr,begin_time,end_time,upload,download,session_duration
%%等信息
%%表结构:-record(stat_session_info_t,{msisdn,teid_i,teid,enduseraddr,begin_time,end_time,upload,
%%              download,session_duration})
%%=========================================================
insert_stat_session_info(BeginTime,EndTime,ReqIpH,ReqGtpH,ReqGtpIES,ResIPH,ResGtpH,ResGtpIes) ->
    Msisdn = find_msisdn_from_ies(ReqGtpIES),
    EndUserAddr = find_end_user_addr_from_req_resp(ReqGtpIES,ResGtpIes),
    case ReqGtpH#gtpp_header.version of
        1 ->
            Teid_c_up   =  find_teid_from_ies(ResGtpIes),
            Teid_c_down  = find_teid_from_ies(ReqGtpIES),
            Teid_u_up  = find_teid_i_from_ies(ResGtpIes),
            Teid_u_down = find_teid_i_from_ies(ReqGtpIES);
        %%%%%%%%%%%%%%%%%%%%%%97 版本 ?
        0 -> 
            Teid_c_up  =  ReqGtpH#gtpp_header.teid,
            Teid_c_down  =  ReqGtpH#gtpp_header.teid,
            Teid_u_up  =  ReqGtpH#gtpp_header.teid,
            Teid_u_down  =  ReqGtpH#gtpp_header.teid
    end,
    ets:insert(stat_session_info_t,
               {Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,EndUserAddr,
                BeginTime,EndTime,
                0,0,0,
                find_apn_from_ies(ReqGtpIES)
               }),
    ok.
%%=========================================================
%%当收到一个新的pdu包的时候，修改表中保存的
%%会话信息（上行流量/下行流量，结束时间）
%%pdu的版本为0的时候97/98版,仅有tid(标识一个隧道)和flow label（标识一个流）
%%pdu的版本为1的时候99版,gtp头中含有teid字段(标识一个隧道)
%%=========================================================
update_stat_session_info(Time,Pdu_packInfo,GtpHeader) ->
    Teid  = GtpHeader#gtpp_header.teid,
    Table = stat_session_info_t,
    F = fun(I) ->
            qlc:q([{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                    End_time,Upload,Download,Session_duration,Apn}
                   || {Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                       End_time,Upload,Download,Session_duration,Apn}  <-  ets:table(Table), (Teid_u_up =:= I  ) or (Teid_u_down  =:=  I)])
        end,
    Q = F(Teid),
    Result = qlc:e(Q),
    update_stat_session(Table,Time,Pdu_packInfo,Result).
%%update endtime,upload,download,session_duration字段
update_stat_session(Table,Time,Pdu_packInfo,
                    [{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                      End_time,Upload,Download,Session_duration,Apn}|T]) ->
    IP_Packet = lists:nth(1,Pdu_packInfo),
    ets:delete(Table,Msisdn),
    SrcIp = util:i_to_ip(IP_Packet#ip_packet.src),
    {N_up,N_down} = case string:equal(Enduseraddr,SrcIp) of
                        true  ->
            {Upload+IP_Packet#ip_packet.totLen,Download};
                        false ->
            {Upload,Download+IP_Packet#ip_packet.totLen}
                    end,
    ets:insert(Table,{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,
                      Enduseraddr,Begin_time,Time,N_up,N_down,Session_duration,Apn});
update_stat_session(_Table,_,_,[]) ->
    ok.

update_session_teid(A_Teid_c_up,A_Teid_c_down,A_Msisdn,
                    A_New_teid_c_up1,A_New_teid_c_down,A_New_teid_u_up,
                    A_New_teid_u_down) ->
    F = fun(A_Teid_c_up,A_Teid_c_down,A_Msisdn,
            A_New_teid_c_up1,A_New_teid_c_down,A_New_teid_u_up,
            A_New_teid_u_down) ->
            qlc:q([{Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                    End_time,Upload,Download,Session_duration,Apn}
                   || {Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
                       End_time,Upload,Download,Session_duration,Apn}
                   <-  ets:table(stat_session_info_t),
                   (Teid_u_up =:= Teid_c_up  ) or (Teid_u_down  =:=  Teid_c_down) and (Msisdn =:= A_Msisdn)
                  ])
        end,
    Q = F(A_Teid_c_up,A_Teid_c_down,A_Msisdn,
          A_New_teid_c_up1,
          A_New_teid_c_down,
          A_New_teid_u_up,
          A_New_teid_u_down),
    Result = qlc:e(Q),
    case Result  of
        [] ->     ok;
        [H|T] -> ets:delete_object(stat_session_info_t,H),
            {Msisdn,Teid_c_up,Teid_c_down,Teid_u_up,Teid_u_down,Enduseraddr,Begin_time,
             End_time,Upload,Download,Session_duration,Apn} = H,
            ets:insert(stat_session_info_t,{Msisdn,A_New_teid_c_up1,A_New_teid_c_down,A_New_teid_u_up,A_New_teid_u_down,Enduseraddr,Begin_time,
                                            End_time,Upload,Download,Session_duration,Apn})
    end.

