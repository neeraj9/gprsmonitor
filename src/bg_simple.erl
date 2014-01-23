%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Braindead simple binary grep implementation.
%% @end
%%%-------------------------------------------------------------------
-module(bg_simple).
-include_lib("eunit/include/eunit.hrl").

%% API
-export([file_foldl/3]).

%%====================================================================
%% API
%%====================================================================

-spec(file_foldl/3 :: (File :: string(),
                       fun((binary(), T) -> T),
                          T) -> T).
file_foldl(File, F, Acc0) ->
    {ok, Bin} = file:read_file(File),
    bg:bfoldl(F, Acc0, Bin).

%%====================================================================
%% Internal functions
%%====================================================================
