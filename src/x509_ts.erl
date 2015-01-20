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

%%  @doc    The {@module} module provides operations for working with
%%          date and time values relevant to X.509 certificates.
%%
%%
-module(x509_ts).

%%  Public constants
-include("x509.hrl").

%%  Private macros
-include("local_defs.hrl").

-export([
    parse/1,
    normalize_year/1, normalize_year/2,
    parse_tz_offset/1,
    parse_time/1,
    parse_dt3/2,
    parse_dt6/2,
    parse_dt7/2
]).

-define(genTimePattern, "~2d~2d~2d~2d~2d~2dZ").
-define(utcTimePattern, "~4d~2d~2d~2d~2d~2dZ").

%%
%%  @doc    Parse the provided timestamp into Gregorian seconds.
%%
%%  If the timestamp's format is not recognized
%%  <code><b>error</b>:{unrecognized, <i>TS</i>}</code> is raised.
%%
-spec parse(TS :: public_key:time() | nonempty_string()) -> x509:gsecs_ts().
parse({utcTime, TS}) ->
    parse_dt6(TS, [?utcTimePattern]);
parse({generalTime, TS}) ->
    parse_dt6(TS, [?genTimePattern]);
parse(TS) when is_list(TS) ->
    parse_ts(TS).

%%
%%  @doc    Parse the specified timestamp into three fields using one of
%%          a specified list of patterns.
%%
%%  Patterns are as specified for {@link io:fread/2}.  The list of patterns is
%%  tried starting from the head, and the first one that matches is used to
%%  produce the result.
%%
%%  The result is assumed to be either a {@link calendar:date()} or
%%  {@link calendar:time()}, though no validation is performed.
%%
%%  If the timestamp does not match any of the specified patterns exactly
%%  (with no unparsed characters)
%%  <code><b>error</b>:{unrecognized, <i>TS</i>}</code> is raised.
%%
-spec parse_dt3(TS :: nonempty_string(),
                Pats :: [nonempty_string()]) -> {any(), any(), any()}.
parse_dt3(TS, []) ->
    error({unrecognized, TS});
parse_dt3(TS, [Pat | Pats]) ->
    case io_lib:fread(Pat, TS) of
        {ok, [F1, F2, F2], []} ->
            {F1, F2, F2};
        _ ->
            parse_dt3(TS, Pats)
    end.

%%
%%  @doc    Parse the specified timestamp into gregorian seconds using one of
%%          a specified list of patterns.
%%
%%  Patterns are as specified for {@link io:fread/2}.  The list of patterns is
%%  tried starting from the head, and the first one that matches is used to
%%  produce the result.
%%
%%  The result is assumed to be a list of six integers, representing year,
%%  month, day, hour, minute, and second, respectively.
%%
%%  The hour is assumed to be in 24-hour format.
%%
%%  The year will be normalized as if by {@link normalize_year/1}.
%%
%%  The time zone is assumed to be UTC.
%%
%%  The resulting values must equate to a well-formed {@link calendar:datetime()},
%%  which is then parsed as if by {@link calendar:datetime_to_gregorian_seconds/1}.
%%
%%  If the timestamp does not match any of the specified patterns exactly
%%  (with no unparsed characters)
%%  <code><b>error</b>:{unrecognized, <i>TS</i>}</code> is raised.
%%
%%  @see    normalize_year/1
%%  @see    calendar:datetime_to_gregorian_seconds/1
%%
-spec parse_dt6(TS :: nonempty_string(),
                Pats :: [nonempty_string()]) -> x509:gsecs_ts().
parse_dt6(TS, []) ->
    error({unrecognized, TS});
parse_dt6(TS, [Pat | Pats]) ->
    case io_lib:fread(Pat, TS) of
        {ok, [Yr, Mo, Dy, Hr, Mn, Ss], []} ->
            calendar:datetime_to_gregorian_seconds(
                {{normalize_year(Yr), Mo, Dy}, {Hr, Mn, Ss}});
        _ ->
            parse_dt6(TS, Pats)
    end.

%%
%%  @doc    Parse the specified timestamp into gregorian seconds using one of
%%          a specified list of patterns.
%%
%%  Patterns are as specified for {@link io:fread/2}.  The list of patterns is
%%  tried starting from the head, and the first one that matches is used to
%%  produce the result.
%%
%%  The result is assumed to be a list of six integers and a trailing string,
%%  representing year, month, day, hour, minute, second, and timezone,
%%  respectively.
%%
%%  The hour is assumed to be in 24-hour format.
%%
%%  The year will be normalized as if by {@link normalize_year/1}.
%%
%%  The timezone is parsed as if by {@link parse_tz_offset/1}.
%%
%%  The values prior to the timezone must equate to a well-formed
%%  {@link calendar:datetime()}, which is then parsed as if by
%%  {@link calendar:datetime_to_gregorian_seconds/1} and adjusted by the
%%  time zone offset from UTC.
%%
%%  If the timestamp does not match any of the specified patterns exactly
%%  (with no unparsed characters)
%%  <code><b>error</b>:{unrecognized, <i>TS</i>}</code> is raised.
%%
%%  @see    normalize_year/1
%%  @see    parse_tz_offset/1
%%  @see    calendar:datetime_to_gregorian_seconds/1
%%
-spec parse_dt7(TS :: nonempty_string(),
                Pats :: [nonempty_string()]) -> x509:gsecs_ts().
parse_dt7(TS, []) ->
    error({unrecognized, TS});
parse_dt7(TS, [Pat | Pats]) ->
    case io_lib:fread(Pat, TS) of
        {ok, [Yr, Mo, Dy, Hr, Mn, Ss, Tz], []} ->
            %%  Get the offset first, since it can fail.
            Off = parse_tz_offset(Tz),
            % ?debugVal(Off),
            %%  Counter-intuitiveness warning!
            %%  The offset is the adjustment applied to UTC to get the string
            %%  we're parsing, so we need to back out that application with
            %%  subtraction, not accumulate it with addition.
            calendar:datetime_to_gregorian_seconds(
                {{normalize_year(Yr), Mo, Dy}, {Hr, Mn, Ss}}) - Off;
        _R ->
            % ?debugFmt("io_lib:fread(~p, ~p) -> ~p", [Pat, TS, _R]),
            parse_dt7(TS, Pats)
    end.

%%
%%  @doc    Parses the specified string and returns the represented offset
%%          from UTC in seconds.
%%
%%  Common timezone offset numeric representations, such as `+/-0', `+/-hmm',
%%  and `+/-hhmm' are recognized, as are the strings `Z', `UTC', and `GMT'
%%  representing UTC, but other alphabetical timezone names/acronyms are not.
%%
%%  If the string does not match any recognizable pattern
%%  <code><b>error</b>:{unrecognized, <i>TZ</i>}</code> is raised.
%%
-spec parse_tz_offset(TZ :: nonempty_string()) -> integer().
parse_tz_offset("Z") -> 0;
parse_tz_offset("+0") -> 0;
parse_tz_offset("-0") -> 0;
parse_tz_offset("UTC") -> 0;
parse_tz_offset("GMT") -> 0;
parse_tz_offset("+0000") -> 0;
parse_tz_offset("-0000") -> 0;
parse_tz_offset([$- | HM] = _S) ->
    % ?debugVal(_S),
    0 - (parse_time(HM) * 60);
parse_tz_offset([$+ | HM] = _S) ->
    % ?debugVal(_S),
    parse_time(HM) * 60;
parse_tz_offset(HM) ->
    % ?debugVal(HM),
    parse_time(HM) * 60.

%%
%%  @doc    Parses the specified 3 or 4 character string and returns the
%%          represented number of minutes or seconds.
%%
%%  The input string is in the form <i>HiLo</i>, where <i>Hi</i> is the number
%%  of high-order elements and <i>Lo</i> is the number of low-order elements,
%%  with each <i>Hi</i> equal to 60 <i>Lo</i>s.  <i>Hi</i> may be represented
%%  by one or two digits, while <i>Lo</i> must always be represented by two
%%  digits.<br />
%%  As such, the string may represent hours and minutes, or minutes and
%%  seconds, and the result is <code>(<i>Hi</i> * 60) + <i>Lo</i></code>.
%%  Neither <i>Hi</i> nor <i>Lo</i> are constrained to being within any range
%%  other than 0..99.
%%
%%  If the string is not comprised of 3 or 4 decimal digits
%%  <code><b>error</b>:{unrecognized, <i>S</i>}</code> is raised.
%%
-spec parse_time(S :: nonempty_string()) -> non_neg_integer().
parse_time([Hi, Lo1, Lo2] = _S) ->
    % ?debugVal(_S),
    parse_time([$0, Hi, Lo1, Lo2]);
parse_time([Hi1, Hi2, Lo1, Lo2] = S) ->
    % ?debugVal(S),
    try {list_to_integer([Hi1, Hi2]), list_to_integer([Lo1, Lo2])} of
        {Hi, Lo} ->
            (Hi * 60) + Lo
    catch
        error:badarg ->
            error({unrecognized, S})
    end;
parse_time(S) ->
    error({unrecognized, S}).

%%
%%  @doc    Normalize a year value to include the century.
%%
%%  If the specified year is greater than 99, it is returned unchanged.<br />
%%  If the specified year is less than zero, the result is the current year
%%  adjusted by the specified value.<br />
%%  If the specified year is in the range 0..99, it is added to the current
%%  or previous century, based on the value of `?X509_TWO_DIGIT_YEAR_PIVOT',
%%  defined in "x509.hrl".
%%
%%  This operation is functionally equivalent to
%%  {@link normalize_year/2. normalize_year(Year, ?X509_TWO_DIGIT_YEAR_PIVOT)}.
%%
-spec normalize_year(Year :: integer()) -> integer().
normalize_year(Year) ->
    normalize_year(Year, ?X509_TWO_DIGIT_YEAR_PIVOT).

%%
%%  @doc    Normalize a year value to include the century.
%%
%%  If the specified year is greater than 99, it is returned unchanged.<br />
%%  If the specified year is less than zero, the result is the current year
%%  adjusted by the specified value.<br />
%%  If the specified year is in the range 0..99, it is added to the current
%%  or previous century, based on the value of Pivot.
%%
%%  If the Pivot value is outside the range 0..99
%%  <code><b>error</b>:{badarg, <i>Pivot</i>}</code> is raised.
%%
-spec normalize_year(Year :: integer(), Pivot :: 0..99 ) -> integer().
normalize_year(_Y, P) when P < 0 orelse P > 99 ->
    error({badarg, P});
normalize_year(Y, _P) when Y > 99 ->
    Y;
normalize_year(Y, _P) when Y < 0 ->
    current_year() + Y;
normalize_year(Y2, P) ->
    SY = current_year(),
    Y = SY rem 100,
    C = SY - Y,
    if Y2 > (Y + P) ->
        C - 100 + Y2;
        true ->
            C + Y2
    end.

%%  @end
%%======================================================================
%%  Internal functions
%%======================================================================

current_year() ->
    {{Y, _, _}, _} = calendar:universal_time(),
    Y.

%%  Patterns:
%%      "YYMMDDhhmmss"
-define(DT_PATTERNS_6_12, ["~2d~2d~2d~2d~2d~2d"]).

%%  Patterns:
%%      "YYMMDDhhmmssZ"
-define(DT_PATTERNS_6_13, [?genTimePattern]).

%%  Patterns:
%%      "YYYYMMDDhhmmss"
-define(DT_PATTERNS_6_14, ["~4d~2d~2d~2d~2d~2d"]).

%%  Patterns:
%%      "YYYYMMDDhhmmssZ"
-define(DT_PATTERNS_6_15, [?utcTimePattern]).

%%  Patterns:
%%      "YYYY-MM-DDThh:mm:ssZ"
%%      picked up by ?DT_PATTERNS_7
-define(DT_PATTERNS_6_20, ["~4d-~2d-~2dT~2d:~2d:~2dZ"]).

%%  Patterns with 7 fields are generally variable length.
%%  Patterns:
%%      "YYYYMMDDhhmmssTZ"
%%      "YYYYMMDDhhmmss TZ"
%%      "YYYY-MM-DDThh:mm:ssTZ"
%%      "YYYY-MM-DDThh:mm:ss TZ"
%%      "YYYY-MM-DD hh:mm:ssTZ"
%%      "YYYY-MM-DD hh:mm:ss TZ"
-define(DT_PATTERNS_7, [
    "~4d-~2d-~2dT~2d:~2d:~2d~s",
    "~4d-~2d-~2d ~2d:~2d:~2d~s",
    "~4d~2d~2d~2d~2d~2d~s"
]).

%%  @private
%%
%%  @doc    Parse a string representation of a timestamp into gregorian seconds.
%%
%%  For efficiency, patterns are grouped by the length of the string(s) they
%%  may match.
%%
%%  An Index is provided to help in cases where recursion MAY be required.
%%
-spec parse_ts(TS :: string()) -> x509:gsecs_ts().
parse_ts(TS) ->
    S = string:strip(TS),
    case length(S) of
        12 ->
            parse_dt6(S, ?DT_PATTERNS_6_12);
        13 ->
            parse_dt6(S, ?DT_PATTERNS_6_13);
        14 ->
            parse_dt6(S, ?DT_PATTERNS_6_14);
        15 ->
            parse_dt6(S, ?DT_PATTERNS_6_15);
        _ ->
            parse_dt7(S, ?DT_PATTERNS_7)
    end.

%%======================================================================
%%  EUnit Tests
%%======================================================================
-ifdef(TEST).

-define(ts2gs(TS), calendar:datetime_to_gregorian_seconds(TS)).
-define(gs2ts(GS), calendar:gregorian_seconds_to_datetime(GS)).

test_macro_test() ->
    D = calendar:universal_time(),
    S = calendar:datetime_to_gregorian_seconds(D),
    % ?debugVal(D),
    % ?debugVal(S),
    ?assertEqual(D, ?gs2ts(?ts2gs(D))),
    ?assertEqual(S, ?ts2gs(?gs2ts(S))).

epoch_macro_test() ->
    Gdt = ?gs2ts(0),
    Pdt = {{1970, 1, 1}, {0, 0, 0}},
    Ges = ?ts2gs(Gdt),
    Pes = ?ts2gs(Pdt),

    % ?debugVal(Gdt),
    % ?debugVal(Pdt),
    % ?debugVal(Ges),
    % ?debugVal(Pes),

    ?assertEqual((Pes - Ges), ?X509_GSECS_POSIX_OFF),
    ?assertEqual(Pdt, ?gs2ts(Ges + ?X509_GSECS_POSIX_OFF)),

    Cdt = calendar:universal_time(),
    Cgs = ?ts2gs(Cdt),
    Cps = (Cgs - ?X509_GSECS_POSIX_OFF),

    % ?debugVal(Cdt),
    % ?debugVal(Cgs),
    % ?debugVal(Cps),

    ?assertEqual(Cps, ?x509_gsecs_to_posix(Cgs)),
    ?assertEqual(Cgs, ?x509_posix_to_gsecs(Cps)).

normalize_year_pivot_test() ->
    Y4 = current_year(),
    Y2 = (Y4 rem 100),
    [?assertEqual(Y4, normalize_year(Y2, P)) || P <- [0, 1, 98, 99]],
    [?assertError({badarg, P}, normalize_year(Y4, P)) || P <- [-111, -1, 100, 222]].

normalize_year_test() ->
    SysY4 = current_year(),
    SysY2 = (SysY4 rem 100),
    SysC4 = (SysY4 - SysY2),
    DfltP = ?X509_TWO_DIGIT_YEAR_PIVOT,
    % ?debugFmt("Using Year: ~B, ~B; Century: ~B; Default Pivot: ~B",
    %     [SysY4, SysY2, SysC4, DfltP]),

    ?assertEqual(SysY4, normalize_year(SysY2)),
    ?assertEqual(SysY4, normalize_year(SysY2, DfltP)),
    ?assertEqual(SysC4, normalize_year(0)),
    ?assertEqual((SysC4 - 1), normalize_year(99)),
    [begin
        Adj4 = if
            Adj2 > DfltP ->
                (Adj2 - 100);
            Adj2 < -SysY2 ->
                (Adj2 + SysY2);
            true ->
                Adj2
        end,
        % ?debugFmt("Adj2 = ~B; Adj4 = ~B", [Adj2, Adj4]),
        ?assertEqual((SysY4 + Adj4), normalize_year(SysY2 + Adj2))
    end || Adj2 <-
        [-49, -SysY2, -3, -1, (DfltP - 1), DfltP, (DfltP + 1), 1, 7, 49]].

parse_ts_test() ->
    [begin
         % ?debugVal(S),
         ?assertEqual(?ts2gs(T), parse_ts(S))
    end || {T, S} <- [
        {{{1968,  7, 15}, { 2, 56, 19}}, "680715025619Z"}
      , {{{1968,  7, 15}, { 2, 56, 19}}, "19680715025619Z"}
      , {{{1971,  1, 10}, {15, 27, 46}}, "710110152746Z"}
      , {{{1971,  1, 10}, {15, 27, 46}}, "19710110152746Z"}
      , {{{1999, 12, 31}, {23, 59, 59}}, "1999-12-31T23:59:59Z"}
      , {{{1999, 12, 31}, {23, 59, 59}}, "1999-12-31 23:59:59 UTC"}
      , {{{1999, 12, 31}, {23, 59, 59}}, "1999-12-31 18:59:59 -500"}
    ]].

-endif. % TEST

