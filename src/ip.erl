-module(ip).
-compile(export_all).
-define(BUFFER_SIZE, (64 * 32)).
start() ->
    read_file(),
    io:format("¿ªÊ¼").


read_file() ->
    {ok, File} = file:open("QQWry.Dat", [raw, binary]),
    read_file_1(File, 0, <<>>).

read_file_1(File, Offset, Remain) ->
    case file:pread(File, Offset, ?BUFFER_SIZE) of
        eof ->
            file:close(File),
            Remain;
        {ok, Bin} ->
            %%process the bin data.......
            %Re = decode_libpcap(<<Remain/binary,Bin/binary>>),
            halt()
            %read_file_1(File, Offset + ?BUFFER_SIZE, Re)
    end.
