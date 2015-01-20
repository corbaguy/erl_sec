%% -------------------------------------------------------------------
%%
%% Copyright (c) 2014,2015 Basho Technologies, Inc.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

%%
%%  @doc    Module for handling passwords typed into a terminal.
%%
%%  Currently, passwords are read from <code>stdin</code>, not from the
%%  terminal device.
%%
-module(passwd).

%%======================================================================
%%  Public API
%%======================================================================
-export([
    getpass/0, getpass/1
]).

%%
%%  @doc    Collects input from the current terminal up to the next newline
%%          without echoing typed characters.  The trailing newline is
%%          stripped and characters are returned verbatim.
%%
%%  End-of-file on input is handled appropriately, but if the I/O server
%%  cannot complete the operation an error containing the reason is raised.
%%
-spec getpass() -> string().
getpass() ->
    getpass("").

%%
%%  @doc    Echoes the specified <code>Prompt</code> to the current
%%          terminal, then collects input up to the next newline
%%          without echoing typed characters.  The trailing newline is
%%          stripped and characters are returned verbatim.
%%
%%  End-of-file on input is handled appropriately, but if the I/O server
%%  cannot complete the operation an error containing the reason is raised.
%%
-spec getpass(Prompt :: string()) -> string().
getpass(Prompt) ->
    OO = io:getopts(),
    ok = io:setopts(pw_io_opts(OO)),
    In = io:get_line(Prompt),
    ok = io:setopts(OO),
    %%  Only write a newline (since the one entered wasn't echoed) if no
    %%  error occurred.
    case In of
        {error, Why} ->
            error(Why);
        _ ->
            io:nl()
    end,
    %%  No error, newline has been written, now proccess the input.
    %%  There should be exactly one newline at the end of the input buffer,
    %%  but it's cheap to handle all cases (like if the behavior changes).
    case In of
        [$\n] ->
            [];
        eof ->
            [];
        [] ->   % this case shouldn't happen
            [];
        Pw ->
            case lists:last(Pw) of
                $\n ->
                    lists:sublist(Pw, length(Pw)-1);
                _ ->    % this case shouldn't happen
                    Pw
            end
    end.

%%======================================================================
%%  Internal functions
%%======================================================================

%%  @private
%%
%%  @doc    Returns appropriate IO options for non-echoed verbatim input
%%          based on current terminal settings.
%%
-spec pw_io_opts(OrigOpts :: [io:opt_pair()]) -> [io:opt_pair()].
pw_io_opts(OrigOpts) ->
    case proplists:is_defined(expand_fun, OrigOpts) of
        true ->
            [{echo, false}, {binary, false},
             {expand_fun, fun(_) -> {yes, "", []} end}];
        _ ->
            [{echo, false}, {binary, false}]
    end.

%%======================================================================
%%  EUnit Tests
%%======================================================================
-ifdef(TEST).


-endif. % TEST

