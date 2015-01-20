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

%%  @doc    The {@module} module provides operations for working with X.509
%%          certificates.
%%
%%  Include `x509.hrl' if needed, but the constants it contains are of
%%  questionable value outside the implementation of X.509 operations.
%%
%%  @see    public_key
%%
-module(x509).

%%  X.509 certificate definitions
-include_lib("public_key/include/public_key.hrl").

%%  Public constants
-include("x509.hrl").

%%  Private macros
-include("local_defs.hrl").

%%======================================================================
%%  Public API
%%======================================================================

%%  Utility functions
-export([
    current_gsecs/0,
    current_psecs/0
]).

%%  Certificate field accessors
-export([
    get_cert_valid_times/1,
    is_valid_now/1
]).

%%  Certificates
-export_type([
    gsecs_ts/0, posix_ts/0,
    plain_cert/0, otp_cert/0, certificate/0,
    privatekey/0,
    certrequest/0,
    cirec/0, certinfo/0,
    certchain/0
]).

%%======================================================================
%%  Types
%%======================================================================

-type gsecs_ts() :: non_neg_integer().
%%  Seconds since the Erlang Gregorian epoch,
%%  <br />The [imaginary] epoch is 1-Jan-0 00:00:00 UTC.
%%  <br />Refer to <a href="http://erlang.org/doc/man/calendar.html">
%%  calendar</a> for details of Erlang's interpretation of Gregorian time.

-type posix_ts() :: integer().
%%  Seconds since the POSIX epoch.
%%  <br />The POSIX epoch is 1-Jan-1970 00:00:00 UTC.

-type otp_cert() :: #'OTPCertificate'{}.
%%  OTP X.509 certificate representation.
%%  <br />This type is more fully expanded into Erlang terms than the
%%  {@link plain_cert()} type.
%%  <br />Refer to
%%  <a href="http://erlang.org/doc/apps/public_key/cert_records.html">
%%  X.509 Certificate Records</a> for details.

-type plain_cert() :: #'Certificate'{}.
%%  Plain X.509 certificate representation.
%%  <br />Refer to
%%  <a href="http://erlang.org/doc/apps/public_key/cert_records.html">
%%  X.509 Certificate Records</a> for details.

-type certificate() :: otp_cert() | plain_cert().
%%  An X.509 certificate representation.

-type privatekey() :: public_key:private_key().
%%  A private key representation.

-type certrequest() :: #'CertificationRequest'{}.
%%  X.509 certificate request.
%%  <br />Refer to
%%  <a href="http://erlang.org/doc/apps/public_key/cert_records.html">
%%  X.509 Certificate Records</a> for details.

-type certchain() :: [certificate()].    %%  An ordered list of certificates.
%%  The head of the list is the certificate that the chain validates, with
%%  each certificate at position <i>N</i> being signed by the certificate at
%%  position <i>N+1</i>.  If the last certificate in the chain is not
%%  self-signed, then it must have been signed by a trusted certificate that
%%  is known to the system by other means (a separately configured trust
%%  store, for instance).

-type ci_name() :: {name, string}.
%%  {@link certinfo()} element containg the simple name of the certificate's
%%  subject, which may, or may not, be a CN.

-type ci_cansign() :: {cansign, boolean()}.
%%  {@link certinfo()} element indicating whether the certificate can sign
%%  other certificates - i.e. it is a CA certificate.

-type ci_selfsigned() :: {selfsigned, boolean()}.
%%  {@link certinfo()} element indicating whether the certificate is
%%  self-signed.  Self-signed certificates are generally, though not always,
%%  used only by root CAs.

-type ci_certfile() :: {certfile, file:filename()}.
%%  {@link certinfo()} element containing the local path to the certificate
%%  file.

-type ci_certurl() :: {certurl, http_uri:uri()}.
%%  {@link certinfo()} element containing the URI path to the certificate file.

-type ci_keyfile() :: {keyfile, file:filename()}.
%%  {@link certinfo()} element containing the local path to the certificate's
%%  private key file.

-type ci_cert() :: {cert, certificate()}.
%%  {@link certinfo()} element containing the record representing the
%%  certificate.

-type ci_key() :: {key, privatekey()}.
%%  {@link certinfo()} element containing the record representing the
%%  certificate's private key.

-type ci_capriv() :: {capriv, term()}.
%%  {@link certinfo()} element containing opaque CA data for later operations.

-type ci_any() :: {atom(), term()}.
%%  {@link certinfo()} element containing anything not otherwise specified.

-type cirec() :: ci_name() | ci_cansign() | ci_selfsigned() | ci_certfile()
    | ci_certurl() | ci_keyfile() | ci_cert() | ci_key() | ci_capriv()
    | ci_any().
%%  A key/value pair that is included in a {@link certinfo()} list.
%%  In fact, no real constraints are placed on this type - it's really just
%%  a {@link proplists:property()}, with some well-known keys whose associated
%%  values are expected to have specified semantics.

-type certinfo() :: [cirec()].
%%  Information about an X.509 certificate.
%%  <br />This is really just a property list, with some well-known element
%%  semantics.

%%  @end
%%======================================================================
%%  API functions
%%======================================================================


%%
%%  Date/Time
%%

%%
%%  @doc    Retrieve the begin and end validity times for a certificate,
%%          as Gregorian seconds.
%%
%%  @see    gsecs_ts()
%%
-spec get_cert_valid_times(Cert :: certificate()) ->
    {Begin :: gsecs_ts(), End :: gsecs_ts()}.
get_cert_valid_times(Cert) when is_record(Cert, 'OTPCertificate') ->
    {'Validity', B, E}
        = Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.validity,
    {x509_ts:parse(B), x509_ts:parse(E)};
get_cert_valid_times(Cert) when is_record(Cert, 'Certificate') ->
    {'Validity', B, E}
        = Cert#'Certificate'.tbsCertificate#'TBSCertificate'.validity,
    {x509_ts:parse(B), x509_ts:parse(E)}.

%%
%%  @doc    Reports whether the specified certificate is within its validity
%%          period at this instant.
%%
-spec is_valid_now(Cert :: certificate()) -> boolean().
is_valid_now(Cert) ->
    {Begin, End} = get_cert_valid_times(Cert),
    CurTime = current_gsecs(),
    if CurTime >= Begin andalso End >= CurTime ->
        true;
        true ->
            false
    end.

%%
%%  @doc    Retrieves the system time in Gregorian seconds.
%%
-spec current_gsecs() -> gsecs_ts().
current_gsecs() ->
    calendar:datetime_to_gregorian_seconds(
        calendar:now_to_datetime(os:timestamp())).

%%
%%  @doc    Retrieves the system time in POSIX seconds.
%%
-spec current_psecs() -> posix_ts().
current_psecs() ->
    ?x509_gsecs_to_posix(current_gsecs()).

%%  @end
%%======================================================================
%%  Internal functions
%%======================================================================


%%  @end
%%======================================================================
%%  EUnit Tests
%%======================================================================
-ifdef(TEST).


-endif. % TEST

