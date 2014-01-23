-module(gtpp_decode).
-export([decode_GTPP_header/1, decode_message/1]).
-include("../include/open-cgf.hrl").
-include("../include/gtp.hrl").
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%作用：解析gtp协议头
%%%本系统仅处理gtp-c,gtp-u协议，版本支持3gpp 1997/1998 ,3gpp 1999两个版本,
%%%其余协议统统直接丢弃
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%version = 0 header_length 20 octers
decode_GTPP_header(<<0:3,1:1,_:3,Snn:1,MSGType:8,MSGLen:16,SeqNum:16,FlowLabel:16,PduNo:32,TidBin:8/binary,Rest/binary>>) ->
    <<A:4,B:4,C:4,D:4,E:4,F:4,G:4,H:4,I:4,J:4,K:4,L:4,M:4,N:4,O:4,P:4>> = TidBin,
    {ok,[Tid],_} = io_lib:fread("~d",binary_to_list(
        iolist_to_binary(io_lib:format("~B~B~B~B~B~B~B~B~B~B~B~B~B~B~B~B",
                                       [B,A,D,C,F,E,H,G,J,I,L,K,N,M,P,O])))),
    {#gtpp_header{version=0, pt=1, modern_header=0,msg_type=decode_msg_type(MSGType), msg_len=MSGLen, seqnum = SeqNum,teid=Tid}, Rest};
%%version = 1,header_length 8 octers
decode_GTPP_header(<<1:3,1:1,_:1,0:1,0:1,0:1,MSGType:8,MSGLen:16,TEID:32,Rest/binary>>)    ->
    {#gtpp_header{version=1, pt=1, modern_header=1,msg_type=decode_msg_type(MSGType), msg_len=MSGLen,teid=TEID}, Rest};
%%version = 1,header_length 12 octers
decode_GTPP_header(<<1:3,1:1, _:1,E:1,S:1,Pn:1,MSGType:8,MSGLen:16,TEID:32,SeqNum:16,PduNo:8,NextHdr:8, Rest/binary>>)    ->
    {#gtpp_header{version=1, pt=1, modern_header=1,msg_type=decode_msg_type(MSGType), msg_len=MSGLen,teid=TEID,seqnum = SeqNum}, Rest};
%%version >1 or gtp' 计费  this server not support
decode_GTPP_header(<<V:3,_:1, _:3,_SH:1,MSGType:8, MSGLen:16,Rest/binary>>) ->
    {not_support_gtp_version, Rest}.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%作用：解析gtp协议的扩展头,数据本身无用直接丢弃
%%%本系统仅处理gtp-c,gtp-u协议，版本支持3gpp 1997/1998 ,3gpp 1999两个版本,
%%%其余协议统统不支持
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
decode_GTPP_EXT_header(<<Rest/binary>>) ->
    Rest.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%作用：解析gtp协议的IE信息，gtp-u携带的上层数据不处理,丢弃
%%%本系统仅处理gtp-c,gtp-u协议，版本支持3gpp 1997/1998 ,3gpp 1999两个版本,
%%%其余协议统统不支持
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
decode_message(Bin)   ->
    case decode_GTPP_header(Bin)  of
        {not_support_gtp_version, _} -> {not_support_gtp_version,[]};
        {Header, Rest}  ->
            %%处理扩展头......................
            Rest1 = decode_GTPP_EXT_header(Rest),
            IES = case Header#gtpp_header.msg_type of
                unknown  ->
                    [];
                invalid_msg_type ->
                    [];
                update_pdp_context_Request ->
                    IEs = decode_ies(Rest1, Header#gtpp_header.version);
                update_pdp_context_response ->
                    IEs = decode_ies(Rest1, Header#gtpp_header.version);
                delete_pdp_context_request ->
                    IEs = decode_ies(Rest1, Header#gtpp_header.version);
                delete_pdp_context_response ->
                    IEs = decode_ies(Rest1, Header#gtpp_header.version);
                gtp_msg_tpdu ->
                    [];
                create_pdp_context_request ->
                    IEs = decode_ies(Rest1, Header#gtpp_header.version);
                    %gtp_cdr_statistics:create_pdp_cntx({Header,IEs});
                create_pdp_context_response ->
                    IEs = decode_ies(Rest1, Header#gtpp_header.version);
                _ ->
                     %%处理IEs
                     []
                     %IEs = decode_ies(Rest1, Header#gtpp_header.version)
            end,
            {Header,IES,Rest1}
    end.

decode_msg_type(0) -> unknown;
decode_msg_type(1) -> echo_request;
decode_msg_type(2) -> echo_response;
decode_msg_type(3) -> version_not_supported;
decode_msg_type(4) -> node_alive_request;
decode_msg_type(5) -> node_alive_response;
decode_msg_type(6) -> redirection_request;
decode_msg_type(7) -> redirection_response;
decode_msg_type(16) ->create_pdp_context_request;
decode_msg_type(17) -> create_pdp_context_response;
decode_msg_type(18) -> update_pdp_context_Request;
decode_msg_type(19) -> update_pdp_context_response;
decode_msg_type(20) -> delete_pdp_context_request;
decode_msg_type(21) -> delete_pdp_context_response;
decode_msg_type(26) -> error_lndication;
decode_msg_type(27) -> pdu_notification_request;
decode_msg_type(28) -> pdu_notification_response;
decode_msg_type(29) -> pdu_notification_reject_request;
decode_msg_type(30) -> pdu_notification_reject_response;
decode_msg_type(31) -> supported_extension_headers_notification;
decode_msg_type(32) -> send_routeing_information_for_gprs_request;
decode_msg_type(33) -> send_routeing_information_for_gprs_response;
decode_msg_type(34) -> failure_report_request;
decode_msg_type(35) -> failure_report_response;
decode_msg_type(36) -> note_ms_gprs_present_request;
decode_msg_type(37) -> note_ms_gprs_present_response;
decode_msg_type(48) -> identification_request;
decode_msg_type(49) -> identification_response;
decode_msg_type(50) -> sgsn_context_request;
decode_msg_type(51) -> sgsn_context_response;
decode_msg_type(52) -> sgsn_context_acknowledge;
decode_msg_type(53) -> forward_relocation_request;
decode_msg_type(54) -> forward_relocation_response;
decode_msg_type(55) -> forward_relocation_complete;
decode_msg_type(56) -> relocation_cancel_request;
decode_msg_type(57) -> relocation_cancel_response;
decode_msg_type(58) -> forward_srns_context;
decode_msg_type(59) -> forward_relocation_complete_acknowledge;
decode_msg_type(60) -> forward_srns_context_acknowledge;
decode_msg_type(240) -> data_record_transfer_request;
decode_msg_type(241) -> data_record_transfer_response;
decode_msg_type(255) -> gtp_msg_tpdu;
decode_msg_type(_)      -> invalid_msg_type. %% not valid for GTP' at least.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%作用：解析信息元素IE
%%%处理所有的IE,不确定哪些业务需要
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
decode_ies(Bin, Version) ->
    decode_ies2(Bin, Version, []).
decode_ies2(<<>>, _, Acc) ->
    ?PRINTDEBUG2("Finished processing IEs, Acc is ~p",[Acc]),
    Acc ++ [<< >>];
decode_ies2(Bin, Version, Acc) ->
    <<Type:8,_/binary>> = Bin,
   %io:format("Type ~p,~n",[Type]),
   case decode_ie(Bin, Version) of
        {userdata,Rest}  ->
            Acc;
       {Decode, Rest} -> decode_ies2(Rest, Version, Acc ++ [Decode])
   end.


%% restart counter
decode_ie(<<0:8, Rest/binary>>, Version) ->
    {userdata,<<0:8, Rest/binary>>};
%% cause decode - could decode further in future...
decode_ie(<<1:8, Value:8, Rest/binary>>, Version) ->
    <<Response_Reject_ind:2, _:6>> = <<Value:8>>,
    case Response_Reject_ind of
	0 -> {{cause, request, Value}, Rest};
	1 -> {{cause, reject, Value}, Rest}; %% unknown, treat as reject as per 29.060 ss 7.7.1
	2 -> {{cause, accept, Value}, Rest};
	3 -> {{cause, reject, Value}, Rest}
    end;

%% imsi
decode_ie(<<2:8, Value:8/binary, Rest/binary>>, _Version) ->
    <<T1:4,T2:4,T3:4,T4:4,T5:4,T6:4,T7:4,T8:4,T9:4,
      T10:4,T11:4,T12:4,T13:4,T14:4,T15:4,T16:4>> = Value,
    Imsi = util:imsi_to_str([T16,T15,T14,T13,T12,T11,T10,T9,T8,T7,T6,T5,T4,T3,T2,T1],[]),
    {{imsi,Imsi},Rest};
%% RAI
decode_ie(<<3:8, Mcc2:4,Mcc1:4,16#F0:4,Mcc3:4,Mnc2:4,Mnc1:4, Lac:16,Rac:8,Rest/binary>>, _Version) ->
    Mcc = Mcc1*100 + Mcc2*10 +Mcc3,
    Mnc = Mnc1*10 + Mnc2,
    {{rai,{mcc,Mcc},{mnc,Mnc},{lac,Lac},{rac,Rac}},Rest};
decode_ie(<<3:8, Mcc2:4,Mcc1:4,Mnc3:4,Mcc3:4,Mnc2:4,Mnc1:4, Lac:16,Rac:8,Rest/binary>>, _Version) ->
    Mcc = Mcc1*100 + Mcc2*10 +Mcc3,
    Mnc = Mnc1*100 + Mnc2*10 + Mnc3,
    {{rai,{mcc,Mcc},{mnc,Mnc},{lac,Lac},{rac,Rac}},Rest};
%% TLLI 4
decode_ie(<<4:8, Value:4/binary, Rest/binary>>, _Version) ->
    {{tlli,Value},Rest};
%% P-TMSI 4
decode_ie(<<5:8, Value:4/binary, Rest/binary>>, _Version) ->
    {{p_tmsi,Value},Rest};
%%
decode_ie(<<6:8, Value:3/binary, Rest/binary>>, _Version) ->
    {{gtp_qos_gprs,Value},Rest};
%% 请求接受 1
decode_ie(<<8:8, _:7,NY:1, Rest/binary>>, _Version) ->
    {{reorder,NY},Rest};
%% 鉴权三元组 28
decode_ie(<<9:8, Rand:16/binary,Sres:4/binary,Kc:8/binary, Rest/binary>>, _Version) ->
    {{auth_tri,Rand,Sres,Kc},Rest};
%% MAP原因 1
decode_ie(<<11:8, Value:8, Rest/binary>>, _Version) ->
    {{map_cause,Value},Rest};
%% P-TMSI签名 3
decode_ie(<<12:8, Value:24, Rest/binary>>, _Version) ->
    {{ptmsi_sig,Value},Rest};
%%MS有效性
decode_ie(<<13:8, Spare:7,NY:1, Rest/binary>>, _Version) ->
    {{ms_valid,NY},Rest};
%% restart counter 1
decode_ie(<<14:8, Value:8, Rest/binary>>, _Version) ->
    {{recovery, Value}, Rest};
%%选择模式selection_mode 1
decode_ie(<<15:8, Spare:6,Mode_v:2, Rest/binary>>, _Version) ->
    case Mode_v of
        0 ->
            {{sel_mode,ms_net_validated,false},Rest};
        1 ->
            {{sel_mode,ms_no_validate,false},Rest};
        2 ->
            {{sel_mode,net_valudate,false},Rest};
        3 ->
            {{sel_mode,reserve,false},Rest}
        end;
%%TEID数据(I)
decode_ie(<<16:8, TEID:16, Rest/binary>>, 0) ->
    {{teid_data_i,TEID},Rest};
decode_ie(<<16:8, TEID:32, Rest/binary>>, _Version) ->
    {{teid_data_i,TEID},Rest};
%%TEID控制面
decode_ie(<<17:8,TEID:32, Rest/binary>>, 1) ->
    {{teid_cp,TEID},Rest};
decode_ie(<<17:8,TEID:16, Rest/binary>>, _Version) ->
    {{teid_cp,TEID},Rest};
%%TEID数据(II)
decode_ie(<<18:8, _:4,NSAPI:4,TEID:4/binary, Rest/binary>>, 1) ->
    {{gtp_u_teid_2,{nsapi,NSAPI},{teid,TEID}},Rest};
decode_ie(<<18:8, _:4,NSAPI:4,Flow_ii:4/binary, Rest/binary>>, 0) ->
    {{gtp_u_teid_2,{nsapi,NSAPI},{flow_ii,Flow_ii}},Rest};
decode_ie(<<18:8, _:4,NSAPI:4,Flow_ii:2/binary, Rest/binary>>, _Version) ->
    {{gtp_u_teid_2,not_support},Rest};
%%撤消指示
decode_ie(<<19:8, Value:8, Rest/binary>>, 1) ->
    {{ms_reason,Value},Rest};
decode_ie(<<19:8, _:7,UNDO:1, Rest/binary>>, 0) ->
    case UNDO of
        0 ->
            {{tear_ind,no,0},Rest};
        1 ->
            {{tear_ind,yes,1},Rest}
    end;
decode_ie(<<19:8, _:7,UNDO:1, Rest/binary>>, _Version) ->
    {{tear_ind,not_support},Rest};       
%%网络服务接入点mm_pdp_nsapi
decode_ie(<<20:8, _:4,NSAPI:4, Rest/binary>>, _Version) ->
    {{mm_pdp_nsapi,NSAPI},Rest};
%%RANAP原因
decode_ie(<<21:8, RANAP:8, Rest/binary>>, _Version) ->
   {{ranap_cause,RANAP},Rest};
%%RAB上下文
decode_ie(<<22:8, _:4,NSAPI:4,DL_SEQ:16,UL_SEQ:16,DL_PDCP_SEQ:16,UL_PDCP_SEQ:16, Rest/binary>>, _Len) ->
    {{rab_cntxt,NSAPI,DL_SEQ,UL_SEQ,DL_PDCP_SEQ,UL_PDCP_SEQ},Rest};
%%短消息业务的无线优先级Radio Priority
decode_ie(<<23:8, _:5,RADIO:3, Rest/binary>>, _Version) ->
    {{rp_sms,RADIO},Rest};
%%无线优先级
decode_ie(<<24:8, NSAPI:4,_:1,RADIO:3, Rest/binary>>, _Version) ->
    {{radio_priority,NSAPI,RADIO},Rest};
%%分组流ID
decode_ie(<<25:8, _:4,NSAPI:4,PktFlowId:8,Value:8, Rest/binary>>, _Len) ->
    {{nsapi,NSAPI},{pkt_flow_id,PktFlowId},Rest};
%%计费特征
decode_ie(<<26:8, Value:2/binary, Rest/binary>>, _Version) ->
    %%todo decode value
    {{chrg_char,Value},Rest};
%%跟踪引用
decode_ie(<<27:8, Value:16, Rest/binary>>, _Version) ->
    {{trace_ref,Value},Rest};
%%跟踪类型
decode_ie(<<28:8, Value:16, Rest/binary>>, _Version) ->
    {{trace_type,Value},Rest};
%%移动台不可达原因
decode_ie(<<29:8, Value:8, Rest/binary>>, _Version) ->
    {{ms_reason,Value},Rest};
%%计费ID
decode_ie(<<127:8, Value:32, Rest/binary>>, _Version) ->
    {{chrg_id,Value},Rest};
%%端用户地址
decode_ie(<<128:8, 2:16,_:4,0:4,1:8,Rest/binary>>, _Version) ->
    {{user_addr,<<"Point to Point Protocol">>},Rest};
decode_ie(<<128:8, 2:16,_:4,_:4,2:8,Rest/binary>>, _Version) ->
    {{user_addr,<<"Octet Stream Protocol">>},Rest};
decode_ie(<<128:8, 2:16,_:4,_:4,_:8,Rest/binary>>, _Version) ->
    {{user_addr,<<"pdp_type_no_ipv4">>},Rest};
decode_ie(<<128:8, IE_len:16,_:4,Pdp_org:4,16#21:8,A/integer, B/integer, C/integer, D/integer,Rest/binary>>, _Version) when IE_len > 2 ->
    Ipv4Addr = iolist_to_binary(io_lib:format(?IP_ADDR_FORMAT, [A,B,C,D])),
    {{user_addr,ipv4,Ipv4Addr},Rest};
decode_ie(<<128:8, IE_len:16,_:4,Pdp_org:4,16#57:8,IPV6:16/binary,Rest/binary>>, _Version) when IE_len > 2 ->
    {{user_addr,ipv6,IPV6},Rest};
decode_ie(<<128:8, IE_len:16,_:4,Pdp_org:4,PDP_TYPE_NO:8,Rest/binary>>, _Version) ->
    {{user_addr,empty_pdp_address},Rest};
%%移动性管理上下文(MM Context)
decode_ie(<<129:8, IE_len:16,Rest/binary>>, _Version) when IE_len < 1  ->
    {{mm_cntxt,empty_mm_cntxt},Rest};
decode_ie(<<129:8, IE_len:16,_:5,CKSN:3,SEC_MOD:2,Count:3,_:3,CK:16/binary,IK:16/binary,Quint_len:16,Rest/binary>>, _Version) when _Version =:=0  ->
    {{mm_cntxt,{cksn,CKSN},{sec_mod,1},{ck,CK},{ik,IK},{quint_len,Quint_len}},Rest};
decode_ie(<<129:8, IE_len:16,_:5,CKSN:3,0:2,Count:3,_:3,CK:16/binary,IK:16/binary,Quint_len:16,Rest/binary>>, _Version)  when _Version =/=0->
    {{mm_cntxt,{cksn,CKSN},{sec_mod,0},{ck,CK},{ik,IK},{quint_len,Quint_len}},Rest};
decode_ie(<<129:8, IE_len:16,_:5,CKSN:3,1:2,Count:3,_:3,CK:8/binary,Rest/binary>>, _Version) when _Version =/=0 ->
    {{mm_cntxt,{cksn,CKSN},{sec_mod,1},{ck,CK}},Rest};
decode_ie(<<129:8, IE_len:16,_:5,CKSN:3,2:2,Count:3,_:3,CK:16/binary,IK:16/binary,Quint_len:16,Rest/binary>>, _Version) when _Version =/=0 ->
    {{mm_cntxt,{cksn,CKSN},{sec_mod,2},{ck,CK},{ik,IK},{quint_len,Quint_len}},Rest};
decode_ie(<<129:8, IE_len:16,_:5,CKSN:3,3:2,Count:3,_:3,CK:16/binary,IK:16/binary,Quint_len:16,Rest/binary>>, _Version)  when _Version =/=0->
    {{mm_cntxt,{cksn,CKSN},{sec_mod,3},{ck,CK},{ik,IK},{quint_len,Quint_len}},Rest};
decode_ie(<<129:8, IE_len:16,_:5,CKSN:3,SEC_MOD:2,Count:3,_:3,CK:16/binary,IK:16/binary,Quint_len:16,Rest/binary>>, _Version) when _Version =/=0 ->
    {{mm_cntxt,{cksn,CKSN},{sec_mod,SEC_MOD},{ck,CK},{ik,IK},{quint_len,Quint_len}},Rest};
decode_ie(<<129:8, IE_len:16,Rest/binary>>, _Version) ->
    {{},Rest};
%%apn addr......
decode_ie(<<131:8,IE_len :16,NameLen:8,Rest/binary>>, _Version)  when  NameLen < 32 ->
    N2_L= IE_len - NameLen-1,
    <<N1:NameLen/binary,N2Bin:N2_L/binary,Rest1/binary>> = Rest,
    {{apn,binary_to_list(decode_apn(N1,N2Bin))},Rest1};
decode_ie(<<131:8,IE_len :16,Apn:IE_len/binary,Rest/binary>>, _Version)  ->
    {{apn,Apn},Rest};
decode_ie(<<131:8,Rest/binary>>, _Version)  ->
    {{apn,"not apn"},Rest};
%%proto_conf_option
decode_ie(<<132:8, IE_len:16,_:IE_len/binary,Rest/binary>>, _Version) ->
    {{proto_conf,132},Rest};
%%gsn_addr
decode_ie(<<133:8, 4:16,A/integer, B/integer, C/integer, D/integer,Rest/binary>>, _Version) ->
    IPv4 = iolist_to_binary(io_lib:format(?IP_ADDR_FORMAT, [A,B,C,D])),
    {{gsn_addr,IPv4},Rest};
decode_ie(<<133:8, 5:16,Addr_type:2,Addr_len:6,A/integer, B/integer, C/integer, D/integer,Rest/binary>>, _Version) ->
    Ipv4Addr = iolist_to_binary(io_lib:format(?IP_ADDR_FORMAT, [A,B,C,D])),
    {{gsn_addr,Ipv4Addr},Rest};
decode_ie(<<133:8, 16:16,_:16/binary,Rest/binary>>, _Version) ->
    {{gsn_addr,ipv6_not_support},Rest};
decode_ie(<<133:8, 17:16,Addr_type:2,Addr_len:6,_:16/binary,Rest/binary>>, _Version) ->
    {{gsn_addr,ipv6_not_support},Rest};
%%MS的国际PSTN/ISDN编号(MSISDN)
decode_ie(<<134:8, Len:16,MSISDN:Len/binary,Rest/binary>>, _Version) ->
    MSISDNStr = decode_msisdn0(MSISDN),
    {{msisdn,MSISDNStr},Rest};
%%服务质量脚本(QoS Profile)
decode_ie(<<135:8,Len:16, A_R_pri:8,_:2,Qos_Delay:3,Qos_Reli:3,QosPeak:4,_:1,QosPerc:3,_:3,QosMean:5,Rest/binary>>, _Version) ->
    
    Len1 = Len - 4,
    %io:format("qos Len1 = ~p, and Rest length = ~p ~n",[Len1,size(Rest)]),

    if Len1 > size(Rest)  ->
            %io:format("Len1 biger ~P,,length ~P ~n",[Len1,length(Rest)]),
            Rest2 = <<>>;
        true ->
            %io:format("Len1 small....~p,~n",[Len1]),
           <<_:Len1/binary,Rest2/binary>> = Rest
    end,
    
    %%todo decode last data.....
    {{qos_umts,{a_r_pri,A_R_pri},{qos_delay,Qos_Delay},{qos_reli,Qos_Reli},{qos_perk,QosPeak},{qos_perc,QosPerc},{qos_mean,QosMean}},Rest2};
%%鉴权五元组
decode_ie(<<136:8,Len:16,RAND:16/binary,XRES_LEN:8,XRES:XRES_LEN/binary,CK:16/binary,IK:16/binary,AUTH_LEN:8,AUTH:AUTH_LEN/binary,Rest/binary>>, _Version) ->
    {{auth_qui,{rand,RAND},{xres,XRES},{ck,CK},{ik,IK},{auth,AUTH}},Rest};
%%计费网关地址IPv4 或者 IPv6
decode_ie(<<251:8,4:16,A/integer, B/integer, C/integer, D/integer,Rest/binary>>, _Version) ->
    IPv4 = iolist_to_binary(io_lib:format(?IP_ADDR_FORMAT, [A,B,C,D])),
    {{chrg_addr,{type,ipv4},{addr,IPv4}},Rest};
decode_ie(<<251:8,16:16,IPv6:16/binary,Rest/binary>>, _Version) ->
    {{chrg_addr,{type,ipv6},{addr,IPv6}},Rest};
decode_ie(<<254:8,L:16,Rest/binary>>, _Version) ->
    io:format("the len:~p,~n",[L]),
    {{gtp_node_addr,L},Rest};
%%
decode_ie(<<Type:8,Rest/binary>>, _Version) ->
    {{not_support_type,Type}, <<>>}.

decode_msisdn0(Bin) ->
    <<_:8,Rest/binary>> = Bin,
    decode_msisdn(Rest,["+"]).
decode_msisdn(<<>>,Acc) ->
    iolist_to_binary(lists:reverse(Acc));
decode_msisdn(<<A1:4,A2:4,Rest/binary>>,Acc)  ->
    Acc1 = case A2 < 10 of
               true ->
                    [integer_to_list(A2)|Acc];
               false ->
                    Acc
           end,
    Acc2 = case A1 < 10 of
               true ->
                    [integer_to_list(A1)|Acc1];
               false ->
                     Acc1
           end,
    case length(Acc2) <17 of
        true ->
            decode_msisdn(Rest,Acc2);
        false ->
            decode_msisdn(<<>>,Acc2)
    end.
%apn name....
decode_apn(H,<<>>) ->
    H;
decode_apn(H,<<NL:8,N1:NL/binary,Rest/binary>>)  ->
    decode_apn(<<H/binary,".",N1/binary>>,Rest).
    










