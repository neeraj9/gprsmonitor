-module(gtp_ets_table_cleaer).
%%%%====================================================================
%%% File    : gtp_packet_file_server.erl
%%% Author  : kebo <huang.kebo@gmail.com>
%%% Description :����ʱ���ets��create pdp,update pdp,delete pdp�е�������
%%% ÿ5����ִ��һ���ֻ�����������ʱ��ִ��һ��
%%% Created :  11 NOV 2009 by my name <huang.kebo@gmail.com>
%%%===================================================================
-export([start_link/0]).
-export([init/1]).
-include_lib("stdlib/include/qlc.hrl").
start_link() ->
    proc_lib:spawn_link(gtp_ets_table_cleaer, init, [self()]).
init(Parent) ->
    io:format("start clear........"),
    loop(Parent).

loop(Parent) ->
    receive
        stop -> true;
        Any ->
            loop(Parent)
    after
            500 -> do_clear(),loop(Parent)
    end.

do_clear() ->
    {Now_seconds,Now_microseconds } = unix_now(),
    sdr_statistics:do_clean(Now_seconds).

unix_now() ->
    %%1800
    Now = {Megaseconds,Seconds,Microseconds} = erlang:now(),
   {Megaseconds*1000000 + Seconds,Microseconds}.





