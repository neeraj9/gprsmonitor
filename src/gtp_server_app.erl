-module(gtp_server_app).
-behaviour(application).
%% Application and Supervisor callbacks
-export([start/2, stop/1, init/1]).
-define(MAX_RESTART,    50).
-define(MAX_TIME,      60).
%%----------------------------------------------------------------------
%% Application behaviour callbacks
%%----------------------------------------------------------------------
start(_Type, _Args) ->
    spawn(gtp_packet_grep_server,start,[]),
    gtp_ets_table_cleaer:start_link(),
    supervisor:start_link({local, ?MODULE}, ?MODULE, [s]).
stop(_S) ->
    ok.
%%----------------------------------------------------------------------
%% Supervisor behaviour callbacks
%%----------------------------------------------------------------------
init([s]) ->
    Gtp_decode_server = {gtp_decode_server,{gtp_decode_server,start_link,[]},permanent,2000,worker, [gtp_decode_server]},
    Sdr_statistics = {sdr_statistics,{sdr_statistics,start_link,[]},permanent,2000,worker, [sdr_statistics]},
    Gtp_message_cdr = {gtp_message_cdr,{gtp_message_cdr,start_link,[]},permanent,2000,worker,[gtp_message_cdr] },
    Dns_sdr_statistics = {dns_sdr_statistics,{dns_sdr_statistics,start_link,[]},permanent,2000,worker,[dns_sdr_statistics]},
    Radius_sdr_statics = {radius_sdr_statics,{radius_sdr_statics,start_link,[]},permanent,2000,worker,[radius_sdr_statics]},
    {ok,
     {_SupFlags = {one_for_one, ?MAX_RESTART, ?MAX_TIME},
      [Gtp_decode_server,
       Sdr_statistics,
       Gtp_message_cdr,
       Dns_sdr_statistics,
       Radius_sdr_statics]
     }
    }.

