-module(dataTest).
-compile([bin_opt_info]).
-export([start/1]).

-define(BUFFER_SIZE, (11 * 1024*32)).%%fast

start(FileName) ->
    Start = erlang:now(),
    %odbc:start(),    
    TableId = ets:new(?MODULE, [duplicate_bag,public, {write_concurrency, true}]),
    L = [wait_result(Worker) || Worker <- read_file(TableId,FileName)],
    print_result(L),
    Stop = erlang:now(),
    io:format("the time :~p ,~n",[time_diff(Start, Stop)]).

read_file(TableId,FileName) ->
    {ok, File} = file:open(FileName, [raw, binary]),
    read_file_1(TableId,File, 0, []).
    
read_file_1(TableId,File, Offset, Workers) ->
    case file:pread(File, Offset, ?BUFFER_SIZE) of
        eof ->
            file:close(File),
            Workers;
        {ok, Bin} ->
            Worker = spawn_worker(self(), fun scan_chunk/1, {TableId,Bin}),
            read_file_1(TableId,File, Offset + ?BUFFER_SIZE, [Worker | Workers])
    end.

 spawn_worker(Parent, F, A) ->
    erlang:spawn_monitor(fun() -> Parent ! {self(), F(A)} end).


wait_result({Pid, Ref}) ->
    receive
        {'DOWN', Ref, _, _, normal} -> receive {Pid, Result} -> Result end;
        {'DOWN', Ref, _, _, Reason} -> exit(Reason)
    end.

scan_chunk({TableId,Bin}) ->
    decodeData(TableId,Bin,0).

 decodeData(TableId,<<>>,N) ->N;
 decodeData(TableId,<<$S,$S,L:8,Bpd_port:8,Su_addr:16/little,Su_port:8,2:8,Equi_type:8,C:8,16#45:8,Bin/binary>>,N) ->
    decodeData(TableId,Bin,N+1);
decodeData(TableId,<<Rest/binary>>,N) ->
    io:format("not support Bin:~p ~n",[Rest]),
    N.

time_diff({A1,A2,A3}, {B1,B2,B3}) ->
    (B1 - A1) * 1000000 + (B2 - A2) + (B3 - A3) / 1000000.0 .
print_result(L) ->
    io:format("the result is :~p ~n",[lists:sum(L)]).

