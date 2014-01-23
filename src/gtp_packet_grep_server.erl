-module(gtp_packet_grep_server).
%%%----------------------------------------------------
%% File    : gtp_packet_grep_server.erl
%% Author  : kebo <huang.kebo@gmail.com>
%% 负责包的远程查找传输
%% 客户端发送filename + offset+len信息。
%% 系统根据这些信息找到这个文件（filename）中的起始位置(offset)
%% 并读出长度len的字节数，并传给客户端显示解析
%% Created :  25 oct 2009 by my name <huang.kebo@gmail.com>
%%%----------------------------------------------------
-compile(export_all).

start() ->
    start(8888).
start(Port) ->
    N = erlang:system_info(schedulers),
    listen(Port, N),
    io:format("gtp_packet_grep_server ready with ~b schedulers on port ~b~n", [N, Port]),
    register(?MODULE, self()),
    receive
        Any -> io:format("~p~n", [Any])
    end.
%% to stop: ehttpd!stop.

listen(Port, N) ->
    Opts = [{active, false},
                binary,
                {packet, 0},
                {reuseaddr, true}],
    {ok, S} = gen_tcp:listen(Port, Opts),
    Spawn = fun(I) ->
                    register(list_to_atom("acceptor_" ++ integer_to_list(I)),
                             spawn_opt(?MODULE, accept, [S, I], [link, {scheduler, I}]))
            end,
    lists:foreach(Spawn, lists:seq(1, N)).

accept(S, I) ->
    case gen_tcp:accept(S) of
        {ok, Socket} -> io:format("~p,~n",[Socket]),spawn_opt(?MODULE, loop, [Socket], [{scheduler, I}]);
        Error    -> erlang:error(Error)
    end,
    accept(S, I).

loop(S) ->
    case gen_tcp:recv(S, 0) of
        {ok, <<Offset:32/big,Len:32/big,FileName/binary>>} ->
            io:format("FileName = ~p offset=~p,len= ~p ~n",[FileName,Offset,Len]),
            {ok, IoDevice} = file:open(binary_to_list(FileName),[raw, binary]),
            case file:pread(IoDevice, Offset, Len) of
                eof ->
                    gen_tcp:send(S, <<>>),
                    file:close(IoDevice);
                {ok, Bin} ->
                    gen_tcp:send(S, Bin),
                    file:close(IoDevice)
            end,            
            gen_tcp:close(S),
            loop(S);
        Error ->
            Error
    end.
