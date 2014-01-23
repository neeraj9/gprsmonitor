-module(gtp_capturer).
-export([start/0, stop/0]).

start() ->
    spawn(fun() ->
		  register(gtp_capturer, self()),
		  process_flag(trap_exit, true),
                  FileName = util:gernate_new_fileName(),
                  {ok, IoDevice} = file:open(FileName, [write,{delayed_write,1024,6000}]),
                  ok = file:write(IoDevice,pcap:generate_pcap_gloabl_healer_bin()),
		  Port = open_port({spawn, "python -u ./gtp_capturer.py"}, [{packet, 2}]),
		  loop({FileName,IoDevice,24},1,Port)
	  end).

stop() ->
    gtp_capturer ! stop.

notify_packet_captured({C_file_name,C_io_device,Offset},N,Packet) ->
    <<Time:64/float,Rest/binary>> = iolist_to_binary(Packet),
    TS_Secs = trunc(Time),
    TS_USecs = trunc((Time-TS_Secs)*1000000),
    PktLen = size(Rest),
    Pkt_With_header = pcap:generate_pcap_packet_header(TS_Secs,TS_USecs,PktLen,Rest),
    Pkt_header_len = PktLen + 16,
    ok = file:write(C_io_device,Pkt_With_header),
    gtp_decode_server:decode(C_file_name,N,Offset,Pkt_header_len,Time,Rest),
    Pkt_header_len.

loop({Filename,IoDevice,Offset},N,Port) ->
    receive
	{Port, {data, Packet}} ->
            {C_file_name,C_io_device,C_Offset} = compute_file_device({Filename,IoDevice,Offset},N),
            Pkt_header_len = notify_packet_captured({C_file_name,C_io_device,C_Offset},N,Packet),
            Offset_new = C_Offset + Pkt_header_len,
	    loop({C_file_name,C_io_device,Offset_new},N+1,Port);
	stop ->
	    Port ! {self(), close},
	    receive
		{Port, closed} ->
		    exit(normal)
	    end;
	{'EXIT', Port, Reason} ->
	    exit({port_terminated,Reason});
        _ ->
           io:format("the received data~n")
    end.

compute_file_device({FileName,C_dev,Offset},Num) ->
    N = Num  rem  40000,
    if N == 0 ->
            file:close(C_dev),
            New_FileName = util:gernate_new_fileName(),
            {ok, New_Dev} = file:open(New_FileName, [write,{delayed_write,1024,6000}]),
            ok = file:write(New_Dev,pcap:generate_pcap_gloabl_healer_bin()),
            {New_FileName,New_Dev,24};
        true ->
            {FileName,C_dev,Offset}
    end.