%% -------------------------------------------------------------------
%%
%% Copyright (c) 2014 Basho Technologies, Inc.
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

%%  The trailing number is random, it exists only to avoid guard conflicts.
-ifndef(X509_HRL_INCLUDED_66522).
-define(X509_HRL_INCLUDED_66522, true).

%%  The point at which a two-digit year pivots from after to before, relative
%%  to the current year. IOW, if a two-digit year is greater than the current
%%  year + this value, then it is interpretted in the prior century.
-define(X509_TWO_DIGIT_YEAR_PIVOT, 20).

%%  The offset, in seconds, between the calendar:gregorian_xxx epoch (in UTC)
%%  and the POSIX epoch (1-Jan-1970 00:00:00 UTC).
%%  Some X.509 operations are implemented in terms of POSIX time.
-define(X509_GSECS_POSIX_OFF, 62167219200).

%%  Convert from Gregorian to POSIX seconds.
-define(x509_gsecs_to_posix(GS), (GS - ?X509_GSECS_POSIX_OFF)).

%%  Convert from POSIX to Gregorian seconds.
-define(x509_posix_to_gsecs(PS), (PS + ?X509_GSECS_POSIX_OFF)).

-endif. % X509_HRL_INCLUDED_66522
