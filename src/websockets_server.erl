%%%-------------------------------------------------------------------
%%% File:      websockets_server.erl
%%% @author    Jebu Ittiachen <jebu@jebu.net> [http://blog.jebu.net/]
%%% @copyright 2010 Jebu Ittiachen
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining a copy
%%% of this software and associated documentation files (the "Software"), to deal
%%% in the Software without restriction, including without limitation the rights
%%% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
%%% copies of the Software, and to permit persons to whom the Software is
%%% furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be included in
%%% all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
%%% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
%%% THE SOFTWARE.
%%%
%%% @doc  
%%%
%%% @end  
%%%
%%% @since 2010-08-26 by Jebu Ittiachen
%%%-------------------------------------------------------------------
-module(websockets_server).
-author('jebu@jebu.net').
-behaviour(gen_server).

-compile([verbose, report_errors, report_warnings, trace, debug_info]).
-define(TCP_OPTIONS, [list, {active, true}, {reuseaddr, true}, {packet, raw}, {keepalive, true}]).
-define(SERVER, ?MODULE).
-define(MAX_CLIENTS, 1024).

-export([start_link/3, start_link/2, stop/0]).

-export([register_client/1, get_connected_client_count/0]).
-export([send/1, send/2, close/0, close/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, 
        terminate/2, code_change/3]).

-record(state, {connected_clients = 0, max_clients = ?MAX_CLIENTS, 
                listen_socket = undefined, listen_port, listen_interface}).
% websockets_server external interface
start_link(Port, Interface) ->
  start_link(Port, Interface, ?MAX_CLIENTS).
start_link(Port, Interface, MaxClients) ->
  error_logger:info_report([{"WebSockets SERVER STARTS"}]),
  case gen_server:start_link({local, ?SERVER}, ?MODULE, [Port, Interface, MaxClients], []) of
    {ok, Server} -> 
      Server ! {listen},
      {ok, Server};
    {error, {already_started, Server}} -> 
      {ok, Server}
  end.

stop() ->
  gen_server:call(?SERVER, stop).
%
register_client(ClientPid) ->
  gen_server:call(?SERVER, {register_client, ClientPid}).
%
get_connected_client_count() ->
  gen_server:call(?SERVER, get_connected_client_count).
%
send(Data) ->
  send(self(), Data).
send(Pid, Data) when is_list(Data) ->
  Pid ! {send, list_to_binary(Data)};
send(Pid, Data) when is_binary(Data) ->
  Pid ! {send, Data};
send(Pid, Data) ->
  Pid ! {send, term_to_binary(Data)}.
%
close() ->
  close(self()).
close(Pid) ->
  Pid ! {close}.
%
% gen_server callbacks
%
init([Port, Interface, MaxClients]) ->
  process_flag(trap_exit, true),
  {ok, #state{listen_port = Port, listen_interface = Interface, max_clients = MaxClients}}.
%
handle_call(stop, _From, State = #state{listen_socket = LSocket}) -> 
  iclose(LSocket),
  {stop, stop_requested, State#state{listen_socket = undefined}};

handle_call({register_client, _}, _, State = #state{connected_clients = A, max_clients = B}) when A >= B ->
  {reply, {error, max_connect}, State};
handle_call({register_client, CPid}, _, State = #state{connected_clients = A}) ->
  erlang:monitor(process, CPid),
  {reply, ok, State#state{connected_clients = A+1}};

handle_call(get_connected_client_count, _, State = #state{connected_clients = A, max_clients = B}) ->
  {reply, {ok, A, B}, State};
handle_call(_, _, State) ->
  {reply, ok, State}.
%
%
handle_cast(_, State) ->
  {noreply, State}.
%
%
handle_info({listen}, State = #state{listen_interface = all, listen_port = Port}) ->
  listen_init(Port, ?TCP_OPTIONS, State);
handle_info({listen}, State = #state{listen_port = Port, listen_interface = Interface}) ->
  {ok, InterfaceIpAddress} = inet_parse:address(Interface),
  listen_init(Port, [{ip, InterfaceIpAddress} | ?TCP_OPTIONS], State);

handle_info({'DOWN', _, process, _, _}, State = #state{connected_clients = A}) ->
  {noreply, State#state{connected_clients = A - 1}};
handle_info({'EXIT', _Pid, _Reason}, State = #state{listen_socket = LSocket}) when LSocket =/= undefined -> 
  iclose(LSocket),
  {noreply, State#state{listen_socket = undefined}};

handle_info(_, State) ->
  {noreply, State}.
%
terminate(_Reason, []) -> 
  ok;
terminate(_Reason, #state{listen_socket = LSocket}) when LSocket =/= undefined -> 
  iclose(LSocket),
  ok.

code_change(_OldVsn, State, _Extra) -> 
  {ok, State}.

%
% internal stuff
%
listen_init(Port, TcpOptions, State) ->
  case catch gen_tcp:listen(Port, TcpOptions) of
    {ok, LSocket} -> 
      spawn_link(fun() -> websockets_worker(LSocket) end),
      {noreply, State#state{listen_socket = LSocket}};
    Error -> 
      {stop, {listen_failed, Error}, State}
  end.
%
websockets_worker(LSocket) ->
  case gen_tcp:accept(LSocket) of
    {ok, Socket} -> 
      CPid = spawn(fun() -> 
        case register_client(self()) of
          ok -> websockets_handshake(Socket);
          E  -> error_logger:info_msg("Client connect disallowed ~p ~n", [E])
        end
      end),
      gen_tcp:controlling_process(Socket, CPid),
      websockets_worker(LSocket);
    {error, closed} -> 
      iclose(LSocket)
  end.
%
websockets_handshake(Socket) ->
  receive
    {tcp, Socket, "<policy-file-request/>" ++ _} ->
      isend(Socket, "<cross-domain-policy><allow-access-from domain=\"*\"" 
                    "to-ports=\"*\" /></cross-domain-policy>" ++ [0]),
      iclose(Socket);
    {tcp, Socket, Data1} ->
      {SSocket, Data, Protocol} = case Data1 of
        "GET " ++ _ -> {Socket, Data1, "ws://"};
        "get " ++ _ -> {Socket, Data1, "ws://"};
        _ ->
          % this is a TLS client HELLO packet oops push it back in
          % switch this to SSL and then continue
          inet:setopts(Socket, [{active, false}]),
          gen_tcp:unrecv(Socket, Data1),
          CertAdditionals = case os:getenv("WS_CACERT_FILE") of
            false -> [];
            CACertFile -> [{cacertfile, CACertFile}]
          end,

          {ok, SSLSocket} = ssl:ssl_accept(Socket, [{certfile, os:getenv("WS_SERVER_CERTIFICATE")}, 
                                                    {keyfile, os:getenv("WS_SERVER_KEY")} | CertAdditionals]),
          {ok, SData} = ssl:recv(SSLSocket, 0),
          ssl:setopts(SSLSocket, [{active, true}]),
          {SSLSocket, SData, "wss://"}
      end,
      {Headers, CSum} = parse_handshake(Data),
      Origin = proplists:get_value("origin", Headers, "null"),
      Host = proplists:get_value("host", Headers, "localhost:8010"),
      [HandlerString | _] = string:tokens(proplists:get_value("get", Headers, "websockets_handler"), "/ "),
      Handshake = 
        case CSum of
          <<>> -> 
            [
              "HTTP/1.1 101 Web Socket Protocol Handshake\r\n",
              "Upgrade: WebSocket\r\n",
              "Connection: Upgrade\r\n"
              "WebSocket-Origin: " ++ Origin ++ "\r\n",
              "WebSocket-Location: " ++ Protocol ++ Host ++ "/" ++ HandlerString ++ "\r\n\r\n"
            ];
          _ ->
            [
              "HTTP/1.1 101 WebSocket Protocol Handshake\r\n",
              "Upgrade: WebSocket\r\n",
              "Connection: Upgrade\r\n"
              "Sec-WebSocket-Origin: " ++ Origin ++ "\r\n",
              "Sec-WebSocket-Location: " ++ Protocol ++ Host ++ "/" ++ HandlerString ++ "\r\n\r\n",
              binary_to_list(CSum)
            ]
        end,
      isend(SSocket, Handshake),
      HandlerModule = list_to_atom(HandlerString),
      code:ensure_loaded(HandlerModule),
      State = 
        case erlang:function_exported(HandlerModule, init, 1) of
          true -> erlang:apply(HandlerModule, init, [[]]);
          false -> []
        end,
      websockets_wait_messages(SSocket, {[], HandlerModule, State}),
      iclose(SSocket);
    Any ->
      error_logger:info_msg("Received ~p waiting for handshake: ~n",[Any]),
      websockets_handshake(Socket)
  end.
%
websockets_wait_messages(Socket, State = {Buffer, Handler, CState}) ->
  receive
    {Type, Socket, Data} when Type == tcp; Type == ssl ->
      {Rest, NState} = handle_data(Buffer, Data, Handler, CState),
      websockets_wait_messages(Socket, {Rest, Handler, NState});
    {Type, Socket, Reason} when Type == tcp_error; Type == ssl_error ->
      error_logger:info_msg("tcp_error on socket ~p ~p ~n", [Socket, Reason]),
      erlang:apply(Handler, terminate, [CState]),
      ok;
    {Type, Socket} when Type == tcp_closed; Type == ssl_closed ->
      error_logger:info_msg("WebSockets stream terminated ~n"),
      erlang:apply(Handler, terminate, [CState]),
      ok;
    {send, Data} ->
      isend(Socket, <<0, Data/binary, 255>>),
      websockets_wait_messages(Socket, State);
    {close} ->
      iclose(Socket),
      erlang:apply(Handler, terminate, [CState]),
      ok;
    Any ->
      NState = erlang:apply(Handler, process_message, [Any, CState]),
      websockets_wait_messages(Socket, {Buffer, Handler, NState})
  end.
%
handle_data([], [0|T], Handler, State) ->
  handle_data([], T, Handler, State);
handle_data(Buffer, [], _, State) ->
  {Buffer, State};
handle_data(Buffer, T, Handler, State) when length(Buffer) > 512 ->
  % too many bytes in buffer we skip
  handle_data([], T, Handler, State);
handle_data(L, [255|T], Handler, State) ->
  Line = lists:reverse(L),
  NState = erlang:apply(Handler, process_command, [Line, State]),
  handle_data([], T, Handler, NState);
handle_data(L, [H|T], Handler, State) ->
  handle_data([H|L], T, Handler, State).
%
parse_handshake(Bytes) ->
  CSumOffset = 
    case lists:reverse(Bytes) of
      [10, 13 |_] -> 0;
      _ -> 8
    end,
  {Headers1, CheckSum} = lists:split(length(Bytes) - CSumOffset, Bytes),
  Headers2 = string:tokens(Headers1, "\r\n"),
  {Headers, Key1, Key2} = 
    lists:foldl(fun
      ([[$G, $E, $T, $  | GetHeader]| []], {Acc, K1, K2}) ->
        {[{"get", GetHeader} | Acc], K1, K2};
      ([_| []], Acc) ->
        Acc;
      ([Key| Val], {Acc, K1, K2}) ->
        [_ | Val1] = string:join(Val, ":"),
        case string:to_lower(Key) of
          "sec-websocket-key1" -> {[{"sec-websocket-key1", Val1} | Acc], parse_key(Val1), K2};
          "sec-websocket-key2" -> {[{"sec-websocket-key2", Val1} | Acc], K1, parse_key(Val1)};
          Key1 -> {[{Key1, Val1} | Acc], K1, K2}
        end;
      (_, Acc) ->
        Acc
    end, {[], 0, 0},
      [string:tokens(H1, ":") || H1 <- Headers2]),
  CSum = case {Key1, Key2} of
    {0, 0} -> <<>>;
    _ -> erlang:md5(<<Key1:32/big, Key2:32/big, (list_to_binary(CheckSum))/binary>>)
  end,
  {Headers, CSum}.
%
parse_key(Key) ->
  parse_key(Key, [], 0).
parse_key([], Numbers, 0) ->
  erlang:list_to_integer(lists:reverse(Numbers));
parse_key([], Numbers, Spaces) ->
  erlang:list_to_integer(lists:reverse(Numbers)) div Spaces;
parse_key([32 | Key], Numbers, Spaces) ->
  parse_key(Key, Numbers, Spaces + 1);
parse_key([C | Key], Numbers, Spaces) when C > 47 andalso C < 58 ->
  parse_key(Key, [C|Numbers], Spaces);
parse_key([_ | Key], Numbers, Spaces) ->
  parse_key(Key, Numbers, Spaces).
%
isend(Socket, Data) when is_tuple(Socket) ->
  ssl:send(Socket, Data);
isend(Socket, Data) ->
  gen_tcp:send(Socket, Data).
%
iclose(Socket) when is_tuple(Socket) ->
  ssl:close(Socket);
iclose(Socket) ->
  gen_tcp:close(Socket).
