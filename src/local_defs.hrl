%%
%%  Copyright 2014 Basho Technologies, Inc.
%%
%%  Licensed under the Apache License, Version 2.0 (the "License");
%%  you may not use this file except in compliance with the License.
%%  You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%%  Unless required by applicable law or agreed to in writing, software
%%  distributed under the License is distributed on an "AS IS" BASIS,
%%  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%  See the License for the specific language governing permissions and
%%  limitations under the License.
%%

%%  Author:     Ted Burghart
%%  Version:    0.0.0
%%  Revision:   0   2014-11-07T16:39:54Z
%%
%%  The trailing number is random, it exists only to avoid guard conflicts.
-ifndef(LOCAL_DEFS_HRL_INCLUDED_77238).
-define(LOCAL_DEFS_HRL_INCLUDED_77238, true).

-ifdef(NOTEST).
-undef(TEST).
-endif. % NOTEST
-ifdef(TEST).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-endif. % TEST

-ifdef(NODEBUG).
-undef(DEBUG).
-endif. % NODEBUG
-ifdef(DEBUG).
-compile([debug_info]).
-endif. % DEBUG

-ifdef(DEBUG).
-define(DebugFmt(Fmt, Vals),
        io:fwrite("==> ~s:~w: " ++ Fmt ++ "~n",
            [?MODULE, ?LINE] ++ (Vals))).
-else.
-define(DebugFmt(Fmt, Vals), ok).
-endif. % DEBUG
-define(DebugLoc(),     ?DebugFmt("<==", [])).
-define(DebugMsg(Msg),  ?DebugFmt("~s", [(Msg)])).
-define(DebugVar(Var),  ?DebugFmt("~s = ~p", [??Var, (Var)])).

-endif. % LOCAL_DEFS_HRL_INCLUDED_77238
