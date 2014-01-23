-module(dsm).
-author("kebo@hotmail.com").

-export([
	 start/0,
	 stop/0
        ]).

start() ->
   application:start(gtp_server_app),
   ok.

stop() ->
    application:stop(gtp_server_app),
    ok.

