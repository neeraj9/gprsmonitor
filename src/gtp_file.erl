-module(gtp_file).
-compile(export_all).
start() ->
    {ok, File} = file:open("gtp.pcap", [raw, binary]),
    {ok, IoDevice} = file:open("one.pcap", [write,{delayed_write,60,60}]),
    case file:pread(File, 0, 105) of
        eof ->
            file:close(File),
            file:close(IoDevice);
        {ok, Bin} ->
            ok = file:write(IoDevice,Bin),
            file:close(File),
            file:close(IoDevice)
    end,
    ok.


