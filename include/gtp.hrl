-define(MAC_ADDR_FORMAT, "~.16B:~.16B:~.16B:~.16B:~.16B:~.16B").
-define(IP_ADDR_FORMAT, "~.10B.~.10B.~.10B.~.10B").
-record(gtp_header, {version,
                     pt,
                     e,
                     s,
                     pn,
                     msg_type,
                     msg_len,
                     tepid,
                     seqnum=0,
                     n_pdu,
                     extensions}).

-record(gtpp_header, {version,
                      pt,
                      modern_header,
                      msg_type,
                      msg_len,
                      teid= <<"">>,
                      tid= <<"">>,
                      seqnum = -1 }).
-record(stat_pdp_connect, {
    begin_time,
    end_time,
    src_ip4,
    src_port,
    des_ip4,
    des_port,
    roam_in,
    success,
    cause,
    response_duration,
    session_duration,
    amount
                          }).

-record(udp_packet, { src_port, dst_port, length, checksum, message_type, payload }).

-record(bootp_packet, { hw_type, addr_length, hops, transaction_id, elapsed, bootp_flags,
  client_ip, your_client_ip, next_server_ip, relay_agent_ip, client_mac, dhcp_server_name,
  boot_file, cookie, options }).

-record(bootp_option, { type, value }).


-record(pcap_pkt, {timestamp,orig_len,data}).
-record(ether, {src,dest,type}).
-record(ip_packet, { src, dst, proto, payload }).


