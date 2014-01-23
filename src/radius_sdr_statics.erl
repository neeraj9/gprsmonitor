-module(radius_sdr_statics).
%%%-------------------------------------------------------------------
%%% File    : radius_sdr_statics.erl
%%% Author  : kebo <huang.kebo@gmail.com>
%%% Description :
%%% Created :
%%%-------------------------------------------------------------------
-behaviour(gen_server).
%% API
-export([start_link/0]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).
-export([process_message/2]).
-record(state, {radius_req_table,radius_stat_t}).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
-include("../include/radius.hrl").
-include("../include/eradius_dict.hrl").
-include_lib("stdlib/include/qlc.hrl").

process_message([Filename,Offset,Num,Time,ProtStack],App) ->
    EthernetHeader =  lists:nth(1,ProtStack),
    IpHeader =  lists:nth(2,ProtStack),
    UdpHeader = lists:nth(3,ProtStack),
    Radius = lists:nth(4,ProtStack),
    Reqid= Radius#rad_pdu.reqid,
    Cmd = Radius#rad_pdu.cmd,
    case Cmd of
        {request,Acc} ->    radius_req(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,Radius);
         {Code,Acc}     ->    radius_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,Radius)
    end;
process_message(_,App)->
    ok.
%%====================================================================
%% API
%%====================================================================
%%dns查询请求
radius_req(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,RadiusReq) ->
    gen_server:call(?MODULE, {radius_req,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,RadiusReq]}).
radius_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,RadiusResp) ->
    gen_server:call(?MODULE, {radius_resp,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,RadiusResp]}).

%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link() ->
    io:format("radius_sdr_statics server starting......~n"),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Radius_req_t = ets:new(radius_query_table, [public,set,{write_concurrency, true}]),
    Radius_stat_t = ets:new(radius_stat_table, [public,bag,{write_concurrency, true}]),
    {ok, #state{radius_req_table=Radius_req_t,radius_stat_t=Radius_stat_t}}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%%-------------------------------------------------------------------

handle_call({radius_req,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,RadiusReq]}, _From, State) ->
    ets:insert(State#state.radius_req_table,{RadiusReq#rad_pdu.reqid,
                                      {Time,EthernetHeader,IpHeader,UdpHeader,RadiusReq,Filename,Offset,Num}}),
    {reply,ok,State};
%%处理pdp创建返回消息
handle_call({radius_resp,[Filename,Offset,Num,Time,_EthernetHeader,IpHeader,UdpHeader,RadiusResp]}, _From, State) ->
    Req_id   =  RadiusResp#rad_pdu.reqid,
    RadiusReqs    =  ets:lookup(State#state.radius_req_table,Req_id),
    
    case RadiusReqs of
        [] ->
            ok;
        [{Id,{Req_Time,Req_EthernetHeader,Req_IpHeader,Req_UdpHeader,Req_Radius,Req_Filename,Req_Offset,Req_Num}}|T] ->
            ets:delete(State#state.radius_req_table,Req_id),  %%
            {Cmd,Acc} = RadiusResp#rad_pdu.cmd,
            {Req_cmd,Req_acc} = Req_Radius#rad_pdu.cmd,
            {Req_TS_Secs,Req_TS_USecs} = Req_Time,
            {TS_Secs,TS_USecs} = Time,
            Username = find_user_name(Req_acc),
            Delay = (TS_Secs-Req_TS_Secs)+(TS_USecs-Req_TS_USecs)/1000000,
            Row = {"radius_req_resp",Req_Num,Req_Time,Num,Time,Id,util:i_to_ip(Req_IpHeader#ip_packet.src),
                 util:i_to_ip(IpHeader#ip_packet.src),
                 "d",Delay,binary_to_list(Username),
                 Req_Filename,Req_Offset,Filename,Offset},
            stat_one_minute_radius(Row,State),
            {db, 'dsm_oracle_node@localhost'} ! Row          
    end,
    {reply,ok,State};
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
%%-------------------------------------------
find_user_name([]) ->
    error;
find_user_name([A|T]) ->
    case A of
        {1, Val} -> Val;
        _  -> find_user_name(T)
    end.


%%统计一份中的数据
stat_one_minute_radius( {_,Req_Num,Req_Time,Num,Time,Id,SrcIp,DescIp, _,Delay,
                         Username,Req_Filename,Req_Offset,Filename,Offset} = Row,State) ->
    Table = State#state.radius_stat_t,
    F = fun() ->
        qlc:q([ {Begin_time,End_time,Src_ip,Desc_ip,Amount,RespCode}
               || {Begin_time,End_time,Src_ip,Desc_ip,Amount,RespCode}
               <- ets:table(Table), Begin_time =< Req_Time,Src_ip == SrcIp,Req_Time =< End_time])
    end,
    Q = F(),
    Result = qlc:e(Q),
    {Begin_time,End_time} =  begin_time_and_end_time(Req_Time),
    case Result of
        [] ->         
            ets:insert(Table,{Begin_time,End_time,SrcIp,DescIp,1,0});
        [{Begin_time,End_time,Src_ip,Desc_ip,Amount,RespCode}|T] ->
            ets:delete_object(Table,{Begin_time,End_time,Src_ip,Desc_ip,Amount,RespCode}),
            ets:insert(Table,{Req_Time,Req_Time,SrcIp,DescIp,Amount+1,0})
    end,
    %%处理所有的统计信息
    insert_into_database_when_is_Expired(State,Begin_time,End_time).

begin_time_and_end_time({Ts,MS}) ->
    Ts1970 = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    {{Year, Month, Day},{Hour, Minute,Second}}
                = Req_time_datetime
                = calendar:gregorian_seconds_to_datetime(Ts1970 + Ts+8*60*60),
            Begin_time = {{Year, Month, Day},{Hour, Minute,0}},
            {{Year0, Month0, Day0},{Hour0, Minute0,Second0}}
            = End_time0
            = calendar:gregorian_seconds_to_datetime(Ts1970 + Ts+8*60*60+60),
            End_time = {{Year0, Month0, Day0},{Hour0, Minute0,0}},
    {Begin_time,End_time}.

insert_into_database_when_is_Expired(State,Begin_time,End_time) ->
    Table = State#state.radius_stat_t,
    {{Y,M,D},{H,M1,S}}  = Begin_time,
    F = fun() ->
        qlc:q([ {Begin_time,{{Year, Month, Day},{Hour, Minute,0}},Src_ip,Desc_ip,Amount,RespCode}
               || {Begin_time,{{Year, Month, Day},{Hour, Minute,0}},Src_ip,Desc_ip,Amount,RespCode}
               <- ets:table(Table), Minute < M1])
    end,
    Q = F(),
    Result = qlc:e(Q),
    lists:foreach(fun({Begin_time,{{Year, Month, Day},{Hour, Minute,0}},Src_ip,Desc_ip,Amount,RespCode}=R) ->
                    {db, 'dsm_oracle_node@localhost'} ! {"stat_radius",Begin_time,
                                                         {{Year, Month, Day},{Hour, Minute,0}},
                                                         Src_ip,Desc_ip,Amount,RespCode,1,1,1},
                    ets:delete_object(Table,R)
                end, Result).






