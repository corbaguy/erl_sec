# --------------------------------------------------------------------
#
# Copyright (c) 2014,2015 Basho Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# --------------------------------------------------------------------

REBAR	?= rebar

PRJDIR	:= $(dir $(lastword $(MAKEFILE_LIST)))

OTPVSN	:= $(shell erl -noshell -eval \
	'io:fwrite("~s",[erlang:system_info(otp_release)]), halt().')

PLTFILE	:= $(PRJDIR)dialyzer_$(OTPVSN).plt

compile ::
	$(REBAR) compile

clean ::
	$(REBAR) clean

test ::
	$(REBAR) eunit

docs ::
	$(REBAR) skip_deps=true doc

dialyzer :: $(PLTFILE) compile
	dialyzer --plt $(PLTFILE) \
		--quiet \
		-Wunmatched_returns \
		-Werror_handling \
		-Wrace_conditions \
		-Wunderspecs \
		ebin

$(PLTFILE) :
	dialyzer --build_plt --output_plt $(PLTFILE) --apps \
		erts kernel stdlib crypto asn1 public_key ssl sasl

