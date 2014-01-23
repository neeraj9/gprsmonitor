-module(dns_sdr_statistics).
%%%-------------------------------------------------------------------
%%% File    : gtp_decode_server.erl
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

-record(state, {dns_query_table}).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include_lib("kernel/src/inet_dns.hrl").

process_message([Filename,Offset,Num,Time,ProtStack],App) ->
    EthernetHeader =  lists:nth(1,ProtStack),
    IpHeader =  lists:nth(2,ProtStack),
    UdpHeader = lists:nth(3,ProtStack),
    DNS_REC = lists:nth(4,ProtStack),
    DNS_HEADER = DNS_REC#dns_rec.header,
    QR = DNS_HEADER#dns_header.qr,
    case QR of
        false -> dns_query_req(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,DNS_REC);
        true  -> dns_query_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,DNS_REC)
    end;
process_message(_,App)->
    ok.
%%====================================================================
%% API
%%====================================================================
%%dns查询请求
dns_query_req(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,DnsQuery) ->
    gen_server:call(?MODULE, {dns_query_req,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,DnsQuery]}).
dns_query_resp(Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,DnsResponse) ->
    gen_server:call(?MODULE, {dns_query_resp,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,DnsResponse]}).

%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link() ->
    io:format("dns_sdr_statistics server starting......~n"),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Dns_query_table = ets:new(dns_query_table, [public,set,{write_concurrency, true}]),
    {ok, #state{dns_query_table=Dns_query_table}}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%%-------------------------------------------------------------------

handle_call({dns_query_req,[Filename,Offset,Num,Time,EthernetHeader,IpHeader,UdpHeader,DnsQuery]}, _From, State) ->
    ets:insert(State#state.dns_query_table,{(DnsQuery#dns_rec.header)#dns_header.id,
                                      {Time,EthernetHeader,IpHeader,UdpHeader,DnsQuery,Filename,Offset,Num}}),
    {reply,ok,State};
%%处理dns查询响应消息
handle_call({dns_query_resp,[Filename,Offset,Num,Time,_EthernetHeader,IpHeader,UdpHeader,DnsResponse]}, _From, State) ->
    Id = (DnsResponse#dns_rec.header)#dns_header.id,
    Rcode = (DnsResponse#dns_rec.header)#dns_header.rcode,
    DnsQuery = ets:lookup(State#state.dns_query_table,Id),   
    case DnsQuery of
        [] ->
            ok;
        [{Id,{Req_Time,Req_EthernetHeader,Req_IpHeader,Req_UdpHeader,Req_DnsQuery,Req_Filename,Req_Offset,Req_Num}}|T] ->
            Domain = (hd(Req_DnsQuery#dns_rec.qdlist))#dns_query.domain,
            ets:delete(State#state.dns_query_table,Id),%%
            {Req_TS_Secs,Req_TS_USecs} = Req_Time,
            {TS_Secs,TS_USecs} = Time,
            Delay = (TS_Secs-Req_TS_Secs)+(TS_USecs-Req_TS_USecs)/1000000,
            {db, 'dsm_oracle_node@localhost'} !
                {"dns_req_resp",Req_Num,Req_Time,Num,Time,Id,util:i_to_ip(Req_IpHeader#ip_packet.src),
                 util:i_to_ip(IpHeader#ip_packet.src),
                 Req_Filename,Req_Offset,Filename,Offset,Rcode,Delay,Domain,"s"}
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