# ------------------------------------------------------------------------
#
# Copyright 2019 WSO2, Inc. (http://wso2.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
#
# ------------------------------------------------------------------------

FROM wso2cellery/auth-server:latest AS build-env
COPY ./components/docker-auth /go/src/github.com/cellery-io/cellery-hub/components/docker-auth/
RUN cd /go/src/github.com/cellery-io/cellery-hub/components/docker-auth/ && echo "replace github.com/cesanta/docker_auth/auth_server v0.0.0-20190831165929-82573a5f102c => /go/src/github.com/cesanta/docker_auth/auth_server" >> go.mod
RUN export GO111MODULE=on && cd /go/src/github.com/cellery-io/cellery-hub/components/docker-auth/ && go build -buildmode=plugin -o /plugins/authz.so cmd/authz/authorization.go
RUN export GO111MODULE=on && cd /go/src/github.com/cellery-io/cellery-hub/components/docker-auth/ && go build -buildmode=plugin -o /plugins/authn.so cmd/authn/authentication.go

FROM ubuntu:18.04
COPY --from=build-env /go/src/github.com/cesanta/docker_auth/auth_server/main /
COPY --from=build-env /plugins/ /plugins/

ENTRYPOINT ["/main"]
CMD ["/config/auth_config.yml"]
EXPOSE 5001
