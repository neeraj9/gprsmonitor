-module(bg_block).
-include_lib("eunit/include/eunit.hrl").
%% API
-export([file_foldl/3]).
-record(state, {dev, blocksize}).
%%====================================================================
%% API
%%====================================================================

-spec(file_foldl/3 :: (File :: string(),
                       fun((binary(), T) -> T),
                          T) -> T).
file_foldl(File, F, Acc0) ->
    file_foldl(File, F, Acc0, [defaults]).
file_foldl(File, F, Acc0, Options) ->
    FullOptions = expand(Options),
    BS = proplists:get_value(blocksize, FullOptions),
    {ok, Dev} = file:open(File, [read,read_ahead,raw,binary]),
    S = #state{dev=Dev,
               blocksize=BS},
    dev_foldl(S, F, Acc0, read(S)).

read(#state{dev=Dev, blocksize=BS}) ->
    file:read(Dev, BS).

% Read a block, parse
dev_foldl(S, F, Acc, {ok, Block}) ->
    block_foldl(S, F, bg:bfoldl(F, Acc, Block));
dev_foldl(S, _F, Acc, _) ->
    finish(S),
    {complete, Acc}.

% Read a block with leftovers from the last block.
dev_foldl(S, F, Acc, {ok, Block}, LeftOver) ->
    Bin = list_to_binary([LeftOver, Block]),
    block_foldl(S, F, bg:bfoldl(F, Acc, Bin));
dev_foldl(S, _F, Acc, _, LeftOver) ->
    finish(S),
    {incomplete, Acc, LeftOver}.

% Handles incomplete block leftovers from bg:foldl
block_foldl(S, F, {incomplete, Acc, LeftOver}) ->
    dev_foldl(S, F, Acc, read(S), LeftOver);
block_foldl(S, F, {complete, Acc}) ->
    dev_foldl(S, F, Acc, read(S)).


finish(#state{dev=Dev}) ->
    file:close(Dev).

%%====================================================================
%% Internal functions
%%====================================================================

expand(Options) ->
    proplists:expand([{defaults, [{blocksize, 512*1024}]}], Options).
