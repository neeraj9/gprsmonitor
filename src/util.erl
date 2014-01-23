-module(util).
-compile(export_all).
-define(MAC_ADDR_FORMAT, "~.16B:~.16B:~.16B:~.16B:~.16B:~.16B").
-define(IP_ADDR_FORMAT, "~.10B.~.10B.~.10B.~.10B").
-define(FILE_NAME_FORMAT, "~.10B-~.10B-~.10B-~.10B-~.10B-~.10B_file.pcap").

extract_ip(Data) ->
	<<A/integer, B/integer, C/integer, D/integer>> = Data,
	io_lib:format(?IP_ADDR_FORMAT, [A,B,C,D]).


i_to_ip(N) ->
    <<A/integer, B/integer, C/integer, D/integer>> = <<N:32>>,
    binary_to_list(iolist_to_binary(io_lib:format(?IP_ADDR_FORMAT, [A,B,C,D]))).

gernate_new_fileName() ->
    now_Str().

now_Str() ->
    {{Y,M,D},{H,M1,S}}  = calendar:local_time(),
    binary_to_list(iolist_to_binary(io_lib:format(?FILE_NAME_FORMAT, [Y,M,D,H,M1,S]))).

extract_mac(Data) -> io_lib:format(?MAC_ADDR_FORMAT, binary_to_list(Data)).
swap(Data) -> list_to_binary( lists:reverse( binary_to_list( Data ) ) ).
extract_binary(Bin, Start, End) -> list_to_binary(binary_to_list(Bin, Start, End)).

imsi_to_str([],Acc) ->
    iolist_to_binary(Acc);
imsi_to_str([H1,H2|T],Acc) ->
    Acc1 = if
               H2 =< 9 ->
                   [integer_to_list(H2)|Acc];
               true ->
                   Acc
           end,
    Acc2 = if
               H1 =< 9 ->
                   [integer_to_list(H1)|Acc1];
               true ->
                   Acc1
           end,
    imsi_to_str(T,Acc2).
