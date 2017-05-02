#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# dnstwist
#
# Generate and resolve domain variations to detect typo squatting,
# phishing and corporate espionage.
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

from flask_api import status
from flask_restful import Resource

from dnstwist import UrlParser, DomainFuzz


class FuzzyDomainsController(Resource):
    def get(self, domain):
        try:
            url = UrlParser(domain)
        except ValueError as err:
            return err, status.HTTP_400_BAD_REQUEST

        domain_fuzz = DomainFuzz(url.domain)
        domain_fuzz.generate()

        result = {
            "domain": domain_fuzz.domain,
            "fuzzy_domains": domain_fuzz.domains
        }

        return result, status.HTTP_200_OK
