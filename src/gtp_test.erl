-module(gtp_test).
-compile([bin_opt_info]).
-export([start/1]).
-define(BUFFER_SIZE, (64 * 32)).
-record(pcap_hdr, {version,tz_correction,sigfigures,snaplen,datalinktype,endianess}).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
start(FileName) ->
    timer:sleep(1000),
    Start = erlang:now(),
    lists:foreach(fun(Filename) -> pcap:parse_file(Filename)  end,                  
                  ["gtp_gp_00001_20100121093638",
                   "gtp_gp_00002_20100121100638",
                   "gtp_gp_00003_20100121103638",
                   "gtp_gp_00004_20100121110638",
                   "gtp_gp_00005_20100121113638",
                   "gtp_gp_00006_20100121120638",
                   "gtp_gp_00007_20100121123638",
                   "gtp_gp_00008_20100121130638",
                   "gtp_gp_00009_20100121133638",
                   "gtp_gp_00010_20100121140638",
                   "gtp_gp_00011_20100121143638",
                   "gtp_gp_00012_20100121150638"]),
    Stop = erlang:now(),
    io:format("the time :~p ,~n",[time_diff(Start, Stop)]).

read_file(FileName) ->
    {ok, File} = file:open(FileName, [raw, binary]),
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

time_diff({A1,A2,A3}, {B1,B2,B3}) ->
    (B1 - A1) * 1000000 + (B2 - A2) + (B3 - A3) / 1000000.0 .