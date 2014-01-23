{application, gtp_server_app,
 [
  {description, "gtp_prot_anl"},
  {vsn, "1.0"},
  {id, "gtp_server"},
  {modules,      [gtpp_decode]},
  {registered,   [gtpp_decode]},
  {applications, [kernel, stdlib]},
  %%
  %% mod: Specify the module name to start the application, plus args
  %%
  {mod, {gtp_server_app, []}},
  {env, []}
 ]
}.
