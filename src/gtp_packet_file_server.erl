-module(gtp_packet_file_server).
%%%%====================================================================
%%% File    : gtp_packet_file_server.erl
%%% Author  : kebo <huang.kebo@gmail.com>
%%% Description :负责文件存储的系统server/考虑扩展到分布式系统中去
%%% 接受来自libcap(c dirver port)抓取的数据包存储到文件系统中
%%% Created :  11 NOV 2009 by my name <huang.kebo@gmail.com>
%%%===================================================================
-behaviour(gen_server).
%% API
-export([start_link/0]).
-export([write_packet_to_file/3]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).
-record(state, {file_dev}).
%%====================================================================
%% API
%%====================================================================
write_packet_to_file(Num,Time,Data) ->
    gen_server:cast(?MODULE, {packet,[Num,Time,Data]}).

%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link() ->
    io:format("gtp_packet_file_server starting......~n"),
    {ok,Pid} = gen_server:start_link({local, ?MODULE}, ?MODULE, [], []),
    {ok,Pid}.

%%====================================================================
%% gen_server callbacks
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init(Args) -> {ok, State} |
%%                         {ok, State, Timeout} |
%%                         ignore               |
%%                         {stop, Reason}
%% Description: Initiates the server
%%--------------------------------------------------------------------
init([]) ->
    {ok, Dev} = file:open(util:now_Str(), [write,{delayed_write,1024,6000}]),
    ok = file:write(Dev,pcap:generate_pcap_gloabl_healer_bin()),
    {ok, #state{file_dev = Dev}}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.
%%--------------------------------------------------------------------
%% Function: handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% Description: Handling cast messages
%%--------------------------------------------------------------------
handle_cast({packet,[Num,Time,Pkt]}, S = #state{file_dev = C_dev}) ->
    TS_Secs = trunc(Time),
    TS_USecs = trunc((Time-TS_Secs)*1000000),
    N = Num rem 40000,
    S1 = if
            N == 0 ->
                file:close(C_dev),
                {ok, Dev} = file:open(util:now_Str(), [write,{delayed_write,1024,6000}]),
                ok = file:write(Dev,pcap:generate_pcap_gloabl_healer_bin()),
                ok = file:write(Dev,pcap:generate_pcap_packet_header(TS_Secs,TS_USecs,size(Pkt),Pkt)),
                #state{file_dev = Dev};
            true ->
                ok = file:write(C_dev,pcap:generate_pcap_packet_header(TS_Secs,TS_USecs,size(Pkt),Pkt)),
                S
        end,     
    {noreply, S1};
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% Description: Handling all non call/cast messages
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Func: code_change(OldVsn, State, Extra) -> {ok, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------


