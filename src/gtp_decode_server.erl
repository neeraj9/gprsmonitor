%%%-------------------------------------------------------------------
%%% File    : gtp_decode_server.erl
%%% Author  : kebo <huang.kebo@gmail.com>
%%% Description :gtp协议解码器server
%%% 接受来自libcap(c dirver port)抓取的数据包解码并交给协议分析处理器处理
%%% Created :  2 Mar 2009 by my name <huang.kebo@gmail.com>
%%%-------------------------------------------------------------------
-module(gtp_decode_server).
-behaviour(gen_server).
%% API
-export([start_link/0]).
-export([decode/5]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).
-record(state, {ddd}).

processPacket(File,N,Offset,PcapHeader,FrameData) ->
    {ProtStack,Rest} = pcap:ethernet(FrameData,[PcapHeader]).
    %sdr_statistics:message([File,Offset,N,hd(ProtStack),tl(ProtStack)]).
    %io:format("N = ~p,~n",[N]).

decode(File,N,Offset,PcapHeader,FrameData) ->
    spawn(fun() ->
                                processPacket(File,N,Offset,PcapHeader,FrameData)
          end).
    %gen_server:cast(?MODULE, {packet,[C_file_name,N,Offset,Pkt_header_len,Time,Packet]}).

start_link() ->
    io:format("gtp_decode_server starting......~n"),
    %eradius_dict:start(),
    spawn(gtp_test,start,["gtp_dp1_00001_20100118101244.pcap"]),
    %spawn(gtp_capturer,start,[]),
    IpFragments_table = ets:new(ip_fragments_table, [public,named_table,set,{write_concurrency, true}]),
    {ok,Pid} = gen_server:start_link({local, ?MODULE}, ?MODULE, [], []),
    {ok,Pid}.

init([]) ->
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast({packet,[Filename,N,Offset,Pkt_header_len,Time,Packet]}, State) ->
    %pcap:ethernet(Packet,[]),
    io:format("time=~p,n=~p ethernet=~p ~n",[Time,N,pcap:ethernet(Packet,[])]),
    %gtp_sdr_statistics:gtp_message([Filename,Offset,Num,Header,Sub_prot]),
    %io:format("No = ~p,Offset=~p,packet_len =~p,file_name=~p ~n",[N,Offset,Pkt_header_len,Filename]),
    {noreply, State};
handle_cast(_Msg, State) ->
    io:format("the sniff Data ~p,~n",[_Msg]),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


