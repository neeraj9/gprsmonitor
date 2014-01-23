-module(gtp_sdr_statistics).
%%%-------------------------------------------------------------------
%%% File    : gtp_decode_server.erl
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

-export([gtp_message/1]).
-export([gtp_message1/4]).
-record(state, {pdp_table,stat_pdp_connect_t,pdp_conn_ct,stat_session_info_t,
                delete_pdp_table,update_pdp_table}).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
-include_lib("stdlib/include/qlc.hrl").

gtp_message1(File,Offset,Num,Len) ->
    {db, 'dsm_packet_node@localhost'}!{Num,Offset,Len,File},
    ok.
gtp_message([Filename,Offset,Num,Pcap_pkt,_SubProt]) ->
    process_gtp_message([Filename,Offset,Num,pcap:pcap_ts(Pcap_pkt),_SubProt]).

process_gtp_message([Filename,Offset,Num,Time,{_,_,_,{_,_,_,{_,_,_,{gtp,GtpHeader,_,_}}}} = _SubProt]) when is_record(GtpHeader,gtpp_header) ->
    %EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo
    {ethernet,EthernetHeader,_,{ip,IpHeader,_,{udp_tcp,UdpHeader,_,{gtp,GtpHeader,GtpIES,Pdu_packInfo}}}} = _SubProt,
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
        gtp_msg_tpdu ->
            gtp_msg_tpdu(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo);
        _ ->
            ok
    end;
process_gtp_message(_)->
    ok.
%%====================================================================
%% API
%%====================================================================
%%创建pdp上下文
create_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    gen_server:call(?MODULE, {create_pdp_cntx,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}).
create_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    gen_server:call(?MODULE, {create_pdp_cntx_resp,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}).
%%更新pdp上下文
update_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    gen_server:call(?MODULE, {update_pdp_cntx,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}).
update_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    gen_server:call(?MODULE, {update_pdp_cntx_resp,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}).
%%delete pdp上下文
delete_pdp_cntx(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    gen_server:call(?MODULE, {delete_pdp_cntx,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}).
delete_pdp_cntx_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES) ->
    gen_server:call(?MODULE, {delete_pdp_cntx_resp,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}).

gtp_msg_tpdu(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo) ->
    gen_server:call(?MODULE, {gtp_msg_tpdu,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo]}).
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link() ->
    io:format("gtp_sdr_statistics starting......~n"),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Pdp_Table = ets:new(pdp_table, [public,set,{write_concurrency, true}]),
    Delete_Table = ets:new(delete_pdp_table, [public,set,{write_concurrency, true}]),
    Update_Table = ets:new(update_pdp_table, [public,set,{write_concurrency, true}]),
    Stat_pdp_conn_t = ets:new(stat_pdp_connect_table, [public,set, {write_concurrency, true}]),
    Stat_session_info_t = ets:new(stat_session_info_t, [public,set,{write_concurrency, true}]),
    {ok, #state{pdp_table = Pdp_Table,stat_pdp_connect_t=Stat_pdp_conn_t,
                delete_pdp_table=Delete_Table,update_pdp_table=Update_Table,
                stat_session_info_t=Stat_session_info_t,pdp_conn_ct=0}}.

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

handle_call({create_pdp_cntx,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}, _From, State) ->
    ets:insert(State#state.pdp_table,{{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.src,IpHeader#ip_packet.dst},
                                      {Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num}}),
    {reply,ok,State};
%%处理pdp创建返回消息
handle_call({create_pdp_cntx_resp,[Filename,Offset,Num,Time,_EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}, _From, State) ->
    Pdp_create_request = ets:lookup(State#state.pdp_table,{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.dst,IpHeader#ip_packet.src}),
    case Pdp_create_request of
        [] ->
            ok;
        [{{SeqNo,Req_src_ip,Req_dest_ip},{Req_Time,_Req_EthernetHeader,Req_IpHeader,Req_UdpHeader,
                                          Req_GtpHeader,Req_GtpIES,Req_Filename,Req_Offset,Req_Num}}|T] ->
            ets:delete(State#state.pdp_table,{SeqNo,Req_src_ip,Req_dest_ip}),%%
            insert_stat_session_info(State,Req_Time,Time,Req_IpHeader,Req_GtpHeader,Req_GtpIES,IpHeader,GtpHeader,GtpIES),
            {db, 'dsm_oracle_node@localhost'} !
                {"create",Req_Time,Time,GtpHeader#gtpp_header.seqnum,util:i_to_ip(Req_src_ip),
                 Req_UdpHeader#udp_packet.src_port,util:i_to_ip(Req_dest_ip),
                 Req_UdpHeader#udp_packet.dst_port,
                 find_cause_from_ies(GtpIES),
                 find_apn_from_ies(Req_GtpIES),
                 find_msisdn_from_ies(Req_GtpIES),
                 find_end_user_addr_from_req_resp(Req_GtpIES,GtpIES),Req_Num,Num,Req_Filename,Req_Offset,Filename,Offset}
    end,
    {reply,ok,State};
%%
handle_call({update_pdp_cntx,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}, _From, State) ->
    Update_request_s = ets:lookup(State#state.update_pdp_table,{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.dst,IpHeader#ip_packet.src}),
    case Update_request_s of
        [] ->
            ets:insert(State#state.update_pdp_table,{{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.src,IpHeader#ip_packet.dst},
                                      {Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num}});
        [{{SeqNo,Resp_src_ip,Resp_dest_ip},{Resp_Time,Resp_EthernetHeader,Resp_IpHeader,Resp_UdpHeader,
                                          Resp_GtpHeader,Resp_GtpIES,Resp_Filename,Resp_Offset,Resp_Num}}|T] ->
            ets:delete(State#state.update_pdp_table,{SeqNo,Resp_src_ip,Resp_dest_ip}),%%
            {db, 'dsm_oracle_node@localhost'} !
                {"update",Num,Offset,Filename,Time,Resp_Num,Resp_Offset,Resp_Filename,Resp_Time,
                 GtpHeader#gtpp_header.seqnum,util:i_to_ip(Resp_src_ip),
                 Resp_UdpHeader#udp_packet.src_port,util:i_to_ip(Resp_dest_ip),
                 Resp_UdpHeader#udp_packet.dst_port,
                 find_cause_from_ies(GtpIES),
                 Resp_GtpHeader#gtpp_header.teid}
    end,
    {reply,ok,State};
handle_call({update_pdp_cntx_resp,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}, _From, State) ->
    Update_request_s = ets:lookup(State#state.update_pdp_table,{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.dst,IpHeader#ip_packet.src}),
    case Update_request_s of
        [] ->
            ets:insert(State#state.update_pdp_table,{{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.src,IpHeader#ip_packet.dst},
                                      {Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num}});
        [{{SeqNo,Req_src_ip,Req_dest_ip},{Req_Time,_Req_EthernetHeader,Req_IpHeader,Req_UdpHeader,
                                          Req_GtpHeader,Req_GtpIES,Req_Filename,Req_Offset,Req_Num}}|T] ->
            ets:delete(State#state.update_pdp_table,{SeqNo,Req_src_ip,Req_dest_ip}),%%
            {db, 'dsm_oracle_node@localhost'} !
                {"update",Req_Num,Req_Offset,Req_Filename,Req_Time,Num,Offset,Filename,Time,
                 GtpHeader#gtpp_header.seqnum,util:i_to_ip(Req_src_ip),
                 Req_UdpHeader#udp_packet.src_port,util:i_to_ip(Req_dest_ip),
                 Req_UdpHeader#udp_packet.dst_port,
                 find_cause_from_ies(GtpIES),                 
                 Req_GtpHeader#gtpp_header.teid}
    end,
    {reply,ok,State};
%%delete_pdp_cntx
handle_call({delete_pdp_cntx,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}, _From, State) ->
    ets:insert(State#state.delete_pdp_table,{{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.src,IpHeader#ip_packet.dst},
                                      {Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Filename,Offset,Num}}),
    {reply,ok,State};
%%=========================================================
%%当收到一个delete pdp包的时候,删除内存表中的统计信息，并把已经
%%统计好的数据插入到oracle中去
%%=========================================================
handle_call({delete_pdp_cntx_resp,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES]}, _From, State) ->
    send_to_oracle([Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES],State),
    %%把会话统计信息插入到库中去
    Teid_H  = GtpHeader#gtpp_header.teid,    
    Table = State#state.stat_session_info_t,
    F = fun(I) ->
        qlc:q([{Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,End_time,Upload,Download,Session_duration,Apn}
               || {Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,End_time,Upload,Download,Session_duration,Apn} <- ets:table(Table), Teid =:= I])
    end,
    Q = F(Teid_H),
    Result = qlc:e(Q),
    case Result of
        [] -> ok;
        [{Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,End_time,Upload,Download,Session_duration,Apn}|T] ->
            {Begin_ts,Begin_us} = Begin_time,
            {End_ts,End_us} = Time,
            %Se_du = End_ts - Begin_ts,
            Se_du = ((End_ts*1000000+End_us) - (Begin_ts*1000000+Begin_us))/1000000,
            {db, 'dsm_session_statistics_node@localhost'}!{Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,Time,Upload,Download,Se_du,Apn},
            ets:delete(Table,Msisdn)
    end,    
    {reply,ok,State};
%%==================================================================================================================
handle_call({gtp_msg_tpdu,[Filename,Offset,Num,Time,_EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES,Pdu_packInfo]}, _From, State) ->
    %%修改临时统计库信息
    update_stat_session_info(State,Time,Pdu_packInfo,GtpHeader),
    {db, 'dsm_oracle_pdu_node@localhost'}!
        {Time,util:i_to_ip(IpHeader#ip_packet.src),UdpHeader#udp_packet.src_port,
         util:i_to_ip(IpHeader#ip_packet.dst),UdpHeader#udp_packet.dst_port,
         GtpHeader#gtpp_header.seqnum,GtpHeader#gtpp_header.msg_len,Filename,Offset,Num,GtpHeader#gtpp_header.teid},
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
    gtp_version_not_support;
find_teid_from_ies([H|T]) ->
    case H of
        {teid_cp,TEID} ->
            TEID;
        _ ->
            find_teid_from_ies(T)
    end.


find_teid_i_from_ies([]) ->
    gtp_version_not_support;
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
    gtp_version_not_support;
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
        " " ->
            find_end_user_addr_from_ies(Req);
        Name ->
            Name
    end.

find_end_user_addr_from_ies([]) ->
    " ";
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
insert_stat_session_info(State,BeginTime,EndTime,ReqIpH,ReqGtpH,ReqGtpIES,ResIPH,ResGtpH,ResGtpIes) ->
    Msisdn = find_msisdn_from_ies(ReqGtpIES),
    EndUserAddr = find_end_user_addr_from_req_resp(ReqGtpIES,ResGtpIes),
    case ReqGtpH#gtpp_header.version of
        1 ->
            Teid_I = find_teid_i_from_ies(ReqGtpIES),
            Teid = find_teid_from_ies(ReqGtpIES);
        %%%%%%%%%%%%%%%%%%%%%%97 版本 ?
        0 -> 
            Teid_I = ReqGtpH#gtpp_header.teid,
            Teid =  ReqGtpH#gtpp_header.teid
    end,
    ets:insert(State#state.stat_session_info_t,{Msisdn,Teid_I,Teid,EndUserAddr,
                                                BeginTime,EndTime,0,0,0,find_apn_from_ies(ReqGtpIES)}),
    ok.
%%=========================================================
%%当收到一个新的pdu包的时候，修改表中保存的
%%会话信息（上行流量/下行流量，结束时间）
%%pdu的版本为0的时候97/98版,仅有tid(标识一个隧道)和flow label（标识一个流）
%%pdu的版本为1的时候99版,gtp头中含有teid字段(标识一个隧道)
%%=========================================================
update_stat_session_info(State,Time,Pdu_packInfo,GtpHeader) ->
    Teid  = GtpHeader#gtpp_header.teid,
    Table = State#state.stat_session_info_t,
    F = fun(I) ->
        qlc:q([{Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,End_time,Upload,Download,Session_duration,Apn}
               || {Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,End_time,Upload,Download,Session_duration,Apn} <- ets:table(Table), Teid_i == I])
    end,
    Q = F(Teid),
    Result = qlc:e(Q),
    update_stat_session(Table,Time,Pdu_packInfo,Result).
%%update endtime,upload,download,session_duration字段
update_stat_session(Table,Time,Pdu_packInfo,[{Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,End_time,Upload,Download,Session_duration,Apn}|T]) ->
    {ip,IP_Packet,_} = Pdu_packInfo,
    ets:delete(Table,Msisdn),
    SrcIp = util:i_to_ip(IP_Packet#ip_packet.src),
    {N_up,N_down} = case string:equal(Enduseraddr,SrcIp) of
                    true  ->
                        {Upload+IP_Packet#ip_packet.totLen,Download};
                    false ->
                        {Upload,Download+IP_Packet#ip_packet.totLen}
                   end,
    ets:insert(Table,{Msisdn,Teid_i,Teid,Enduseraddr,Begin_time,Time,N_up,N_down,Session_duration,Apn});
update_stat_session(_Table,_,_,[]) ->
    ok.


send_to_oracle([Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,GtpHeader,GtpIES],State) ->
    Pdp_delete_request = ets:lookup(State#state.delete_pdp_table,{GtpHeader#gtpp_header.seqnum,IpHeader#ip_packet.dst,IpHeader#ip_packet.src}),
    case Pdp_delete_request of
        [] ->
            ok;
        [{{SeqNo,Req_src_ip,Req_dest_ip},{Req_Time,_Req_EthernetHeader,Req_IpHeader,Req_UdpHeader,
                                          Req_GtpHeader,Req_GtpIES,Req_Filename,Req_Offset,Req_Num}}|T] ->
            ets:delete(State#state.delete_pdp_table,{SeqNo,Req_src_ip,Req_dest_ip}),%%
            {db, 'dsm_oracle_node@localhost'} !
                {"delete",Req_Num,Req_Offset,Req_Filename,Req_Time,Num,Offset,Filename,Time,
                 GtpHeader#gtpp_header.seqnum,util:i_to_ip(Req_src_ip),
                 Req_UdpHeader#udp_packet.src_port,util:i_to_ip(Req_dest_ip),
                 Req_UdpHeader#udp_packet.dst_port,
                 find_cause_from_ies(GtpIES),                 
                  Req_GtpHeader#gtpp_header.teid}
    end.
