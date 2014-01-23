-module(bg).
-include_lib("eunit/include/eunit.hrl").
%% API
-export([bmap/5,bfoldl/3]).

bmap(_F,_Endianess,<<>>,_N,_) ->
    ok;
bmap(F, Endianess,Binary,N,Offset)   when is_function(F, 4), is_binary(Binary) ->
    case F(Endianess,Binary,N,Offset) of
           Rest  when is_binary(Rest) ->
                    Len = size(Binary) - size(Rest),
           bmap(F, Endianess,Rest,N+1,Offset + Len);
        _ ->
            ok
    end.

bfoldl(F, Acc, Binary) when is_function(F, 2), is_binary(Binary) ->
    case F(Binary, Acc) of
        {more, Acc1, <<>>} ->
            {complete, Acc1};
        {more, Acc1, Rest} when is_binary(Rest) ->
            bfoldl(F, Acc1, Rest);
        {incomplete, Acc1, Rest} ->
            {incomplete, Acc1, Rest}
    end.