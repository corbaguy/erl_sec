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

-module(x509_io).

%%  X.509 certificate definitions
-include_lib("public_key/include/public_key.hrl").

%%  Private macros
-include("local_defs.hrl").

%% ====================================================================
%% Public API
%% ====================================================================
-export([
    read_certs/1,
    read_cert_file/1,
    read_key_file/1
]).

-export_type([

]).

%% ====================================================================
%% Types
%% ====================================================================


%% ====================================================================
%% API functions
%% ====================================================================

%%
%%  @doc    Given a file or directory path, returns a list of records of type
%%          {@link x509:certificate()} representing all of the identifiable,
%%          unencrypted X.509 certificates at or below the specified Path.
%%
%%  The returned certificates HAVE NOT been verified in any way beyond
%%  successfully parsing them.  See {@link read_cert_file/1} for details
%%  about how each located file is evaluated and parsed.
%%
%%  Duplicates are removed from the result set, but otherwise NO ordering is
%%  assured.
%%
%%  If the operation cannot be completed successfully, an error is raised,
%%  most likely containing one of the {@link file:posix()} reasons and, if
%%  you're lucky, possibly the path where the error occurred.
%%
-spec read_certs(Path :: file:filename_all()) -> [x509:certificate()].
read_certs(FileOrDirPath) ->
    case filelib:is_file(FileOrDirPath) of
        true ->
            case filelib:is_dir(FileOrDirPath) of
                true ->
                    read_cert_dir(FileOrDirPath, []);
                _ ->
                    read_cert_file(FileOrDirPath)
            end;
        _ ->
            error({enoent, FileOrDirPath})
    end.

%%
%%  @doc    Read a single file and return its certificates as a list of
%%          records of type {@link x509:certificate()}.
%%
%%  Filename extensions are considered as follows, regardless of case:
%%
%%  Files with extension ".der" are assumed to be binary DER-encoded
%%  certificates, and if they cannot be parsed as such they are ignored.
%%
%%  Files with extension ".pem" are assumed to be PEM-encoded, and any
%%  entities identified as certificates are decoded.
%%
%%  Files with extension ".key" are assumed to be private keys, in any format,
%%  and are ignored.
%%
%%  All other files are first parsed as binary DER-encoded certificates,
%%  and if that fails they are re-tried as PEM-encoded, as above.
%%
%%  If the operation cannot be completed successfully, an error is raised,
%%  most likely containing one of the {@link file:posix()} reasons and the
%%  path where the error occurred.
%%
-spec read_cert_file(Path :: file:filename_all()) -> [x509:certificate()].
read_cert_file(Path) ->
    ?DebugVar(Path),
    Data = case file:read_file(Path) of
        {ok, Bytes} ->
            Bytes;
        {error, Why} ->
            error({Why, Path})
    end,
    case string:to_lower(filename:extension(Path)) of
        %%  Let's assume that if it's named *.key, it's not a certificate!
        ".key" ->
            [];
        ".der" ->
            case decode_cert_data_der(Data) of
                notder ->
                    [];
                Cert ->
                    [Cert]
            end;
        ".pem" ->
            decode_cert_data_pem(Data);
        _ ->
            case decode_cert_data_der(Data) of
                notder ->
                    decode_cert_data_pem(Data);
                Cert ->
                    [Cert]
            end
    end.

%%
%%  @doc    Read a single file and return its certificates as a list of
%%          records of type {@link x509:certificate()}.
%%
%%  Filename extensions are considered as follows, regardless of case:
%%
%%  Files with extension ".der" are assumed to be binary DER-encoded
%%  certificates, and if they cannot be parsed as such they are ignored.
%%
%%  Files with extension ".pem" are assumed to be PEM-encoded, and any
%%  entities identified as certificates are decoded.
%%
%%  Files with extension ".key" are assumed to be private keys, in any format,
%%  and are ignored.
%%
%%  All other files are first parsed as binary DER-encoded certificates,
%%  and if that fails they are re-tried as PEM-encoded, as above.
%%
%%  If the operation cannot be completed successfully, an error is raised,
%%  most likely containing either the atom 'notkey' or one of the
%%  {@link file:posix()} reasons, and the path where the error occurred.
%%
-spec read_key_file(Path :: file:filename_all()) -> x509:privatekey().
read_key_file(Path) ->
    ?DebugVar(Path),
    Data = case file:read_file(Path) of
        {ok, Bytes} ->
            Bytes;
        {error, Why} ->
            error({Why, Path})
    end,
    Res = case string:to_lower(filename:extension(Path)) of
        ".der" ->
            decode_priv_key_data_der(Data);
        ".pem" ->
            decode_priv_key_data_pem(Data);
        _ ->
            case decode_priv_key_data_der(Data) of
                notder ->
                    decode_priv_key_data_pem(Data);
                K ->
                    K
            end
    end,
    case Res of
        notder ->
            error({notkey, Path});
        Key ->
            Key
    end.

%% ====================================================================
%% Internal functions
%% ====================================================================

-spec read_cert_paths(Paths :: [file:filename_all()],
                      Certs :: [x509:certificate()]) -> [x509:certificate()].
read_cert_paths([], Certs) ->
    Certs;
read_cert_paths([Path|Paths], Certs) ->
    case filelib:is_dir(Path) of
        true ->
            read_cert_paths(Paths, read_cert_dir(Path, Certs));
        false ->
            read_cert_paths(Paths, collect_certs(Certs, read_cert_file(Path)))
    end.

-spec read_cert_dir(Path  :: file:filename_all(),
                    Certs :: [x509:certificate()]) -> [x509:certificate()].
read_cert_dir(Path, Certs) ->
    Result = file:list_dir(Path),
    case Result of
        {ok, []} ->
            [];
        {ok, Paths} ->
            CertPaths = [filename:join(Path, P) || P <- Paths],
            read_cert_paths(CertPaths, Certs);
        {error, Why} ->
            error({Why, Path})
    end.

-spec collect_certs(CertList :: [x509:certificate()],
                    AddCerts :: [x509:certificate()]) -> [x509:certificate()].
collect_certs(CertList, []) ->
    CertList;
collect_certs(CertList, [Cert|Certs]) ->
    case list_contains_key(CertList, get_cert_key(Cert)) of
        true -> collect_certs(CertList, Certs);
        false -> collect_certs(CertList ++ [Cert], Certs)
    end.

-type cert_key() :: binary().

-spec list_contains_key(Certs :: [x509:certificate()],
                        Key :: cert_key()) -> boolean().
list_contains_key([], _Key) ->
    false;
list_contains_key([Cert|Certs], Key) ->
    case Key =:= get_cert_key(Cert) of
        true -> true;
        false -> list_contains_key(Certs, Key)
    end.

-spec get_cert_key(Cert :: x509:certificate()) -> cert_key().
get_cert_key(Cert) when is_record(Cert, 'OTPCertificate') ->
    {0, Sig} = Cert#'OTPCertificate'.signature,
    Sig;
get_cert_key(Cert) when is_record(Cert, 'Certificate') ->
    {0, Sig} = Cert#'Certificate'.signature,
    Sig.

-spec decode_cert_data_der(Data :: binary()) -> [x509:certificate()] | notder.
decode_cert_data_der(Data) ->
    try public_key:pkix_decode_cert(Data, otp) of
        Cert -> [Cert]
    catch
        error:_Reason ->
            ?DebugVar(_Reason),
            notder
    end.

-spec decode_cert_data_pem(Data :: binary()) -> [x509:certificate()].
decode_cert_data_pem(Data) ->
    Entities = public_key:pem_decode(Data),
    [public_key:pkix_decode_cert(DER, otp) ||
        {'Certificate', DER, not_encrypted} <- Entities].

-define(PRIV_KEY_TYPES, [
    'RSAPrivateKey', 'DSAPrivateKey', 'ECPrivateKey', 'PrivateKeyInfo'
]).

-spec decode_priv_key_data_der(Data :: binary()) -> x509:privatekey() | notder.
decode_priv_key_data_der(Data) ->
    decode_data_der(?PRIV_KEY_TYPES, Data).

-spec decode_priv_key_data_pem(Data :: binary()) -> x509:privatekey() | notder.
decode_priv_key_data_pem(Data) ->
    decode_first_priv_key_der(public_key:pem_decode(Data)).

-spec decode_first_priv_key_der(Ents :: [public_key:pem_entry()]) ->
    x509:privatekey() | notder.
decode_first_priv_key_der([Ent | Ents]) ->
    case Ent of
        {Type, DER, not_encrypted} ->
            case lists:any(fun(T) -> T =:= Type end, ?PRIV_KEY_TYPES) of
                true ->
                    decode_data_der([Type], DER);
                _ ->
                    decode_first_priv_key_der(Ents)
            end;
        _ ->
            decode_first_priv_key_der(Ents)
    end.

-spec decode_data_der(Types :: [atom()], Data :: public_key:der_encoded()) ->
    tuple() | notder.
decode_data_der([], _) ->
    notder;
decode_data_der([Type], Data) ->
    try public_key:der_decode(Type, Data) of
        Result -> Result
    catch
        error:_Reason ->
            ?DebugFmt("public_key:der_decode(~p, _): error:~p", [Type, _Reason]),
            notder
    end;
decode_data_der([Type | Types], Data) ->
    case decode_data_der([Type], Data) of
        notder ->
            decode_data_der(Types, Data);
        Result ->
            Result
    end.

%% ====================================================================
%% Tests
%% ====================================================================
-ifdef(TEST).

x509_io_test_() ->
    case is_x509_ca_available() of
        true ->
            [
            ];
        false ->
            []
    end.

is_x509_ca_available() ->
    false.

-endif. % TEST
