-module(radius_decode).
-include("../include/radius.hrl").
-include("../include/eradius_dict.hrl").
-compile(export_all).

%% Ret: #rad_pdu | Reason
dec_packet(Packet) ->
    case catch dec_packet0(Packet) of
	{'EXIT', Reason} ->
	    {error,Reason};
	Else ->
	    {ok,Else}
    end.

dec_packet0(Packet) ->
    <<Cmd:8, ReqId:8, Len:16, Auth:16/binary, Attribs0/binary>> = Packet,
    Size = size(Attribs0),
    Attr_len = Len - 20,
    Attribs =
	if
	    Attr_len > Size ->
		throw(bad_pdu);
	    Attr_len == Size ->
		Attribs0;
	    true ->
		<<Attribs1:Attr_len/binary, _/binary>> = Attribs0,
		Attribs1
	end,
    P = #rad_pdu{reqid = ReqId, authenticator = Auth},
    case Cmd of
	?RAccess_Request ->
	    P#rad_pdu{cmd = {request, dec_attributes(Attribs)}};
	?RAccess_Accept ->
	    P#rad_pdu{cmd = {accept, dec_attributes(Attribs)}};
	?RAccess_Challenge ->
	    P#rad_pdu{cmd = {challenge, dec_attributes(Attribs)}};
	?RAccess_Reject ->
	    P#rad_pdu{cmd = {reject, dec_attributes(Attribs)}};
	?RAccounting_Request ->
	    P#rad_pdu{cmd = {accreq, dec_attributes(Attribs)}};
	?RAccounting_Response ->
	    P#rad_pdu{cmd = {accresp, dec_attributes(Attribs)}}
    end.
-define(dec_attrib(A0, Type, Val, A1),
	<<Type:8, __Len0:8, __R/binary>> = A0,
	__Len1 = __Len0 - 2,
	<<Val:__Len1/binary, A1/binary>> = __R).


dec_attributes(As) ->
    dec_attributes(As, []).

dec_attributes(<<>>, Acc) -> Acc;
dec_attributes(A0, Acc) ->
  ?dec_attrib(A0, Type, Val, A1),
  dec_attributes(A1, [{Type, Val} | Acc]).

dec_attr_val(A, Bin) when A#attribute.type == string ->
    [{A, binary_to_list(Bin)}];
dec_attr_val(A, I0) when A#attribute.type == integer ->
    L = size(I0)*8,
    case I0 of
        <<I:L/integer>> ->
            [{A, I}];
        _ ->
            [{A, I0}]
    end;
dec_attr_val(A, <<B,C,D,E>>) when A#attribute.type == ipaddr ->
    [{A, {B,C,D,E}}];
dec_attr_val(A, Bin) when A#attribute.type == octets ->
    case A#attribute.id of
	?RVendor_Specific ->
	    <<VendId:32/integer, VendVal/binary>> = Bin,
	    dec_vend_attr_val(VendId, VendVal);
	_ ->
	    [{A, Bin}]
    end;
dec_attr_val(A, Val) ->
    io:format("Uups...A=~p~n",[A]),
    [{A, Val}].

dec_vend_attr_val(_VendId, <<>>) -> [];
dec_vend_attr_val(VendId, <<Vtype:8, Vlen:8, Vbin/binary>>) ->
    Len = Vlen - 2,
    <<Vval:Len/binary,Vrest/binary>> = Vbin,
    Vkey = {VendId,Vtype},
    case eradius_dict:lookup(Vkey) of
	[A] when record(A, attribute) ->
	    dec_attr_val(A, Vval) ++ dec_vend_attr_val(VendId, Vrest);
	_ ->
	    [{Vkey,Vval} | dec_vend_attr_val(VendId, Vrest)]
    end.


%%% ====================================================================
%%% Radius Accounting specifics
%%% ====================================================================



patch_authenticator(Req,Secret) ->
    case {erlang:md5([Req,Secret]),concat_binary(Req)} of
	{Auth,<<Head:4/binary, _:16/binary, Rest/binary>>} ->
	    B = l2b(Auth),
	    <<Head/binary, B/binary, Rest/binary>>;
	_Urk ->
	    exit(patch_authenticator)
    end.



l2b(L) when list(L)   -> list_to_binary(L);
l2b(B) when binary(B) -> B.

