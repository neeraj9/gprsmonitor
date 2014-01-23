-module(prot_port_map).
-author(huang.kebo@gmail.com).
-compile(export_all).


protoctl(Port)  ->
    case Port of
            80   -> {http};
            2152 -> {gtp}
    end.








