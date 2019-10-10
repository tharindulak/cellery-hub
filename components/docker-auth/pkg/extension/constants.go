/*
 * Copyright (c) 2019 WSO2 Inc. (http:www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http:www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package extension

const userAdminRole = 3 // Admin, push, pull roles are denoted by 3, 2, 1 respectively.
const userPushRole = 2

const MysqlUserEnvVar = "MYSQL_USER"
const MysqlPasswordEnvVar = "MYSQL_PASSWORD"
const MysqlHostEnvVar = "MYSQL_HOST"
const MysqlPortEnvVar = "MYSQL_PORT"
const MysqlDriver = "mysql"
const DbName = "CELLERY_HUB"
const IdpUsernameEnvVar = "USERNAME"
const IdppasswordEnvVar = "PASSWORD"

const MaxOpenConnectionsEnvVar = "MAX_OPEN_CONNECTIONS"
const MaxIdleConnectionsEnvVar = "MAX_IDLE_CONNECTIONS"
const ConnectionMaxLifetimeEnvVar = "MAX_LIFE_TIME"

const pullAction = "pull"
const pushAction = "push"
const deleteAction = "delete"
const publicVisibility = "PUBLIC"

// db queries
const getVisibilityQuery = "SELECT VISIBILITY FROM REGISTRY_ARTIFACT_IMAGE " +
	"INNER JOIN REGISTRY_ORGANIZATION ON REGISTRY_ORGANIZATION.ORG_NAME=REGISTRY_ARTIFACT_IMAGE.ORG_NAME " +
	"WHERE REGISTRY_ARTIFACT_IMAGE.IMAGE_NAME=? AND " +
	"REGISTRY_ORGANIZATION.ORG_NAME=? LIMIT 1"
const checkOwnerQuery = "SELECT 1 FROM " +
	"REGISTRY_TEAM_USER_MAPPING " +
	"INNER JOIN REGISTRY_ORG_TEAM_MAPPING ON REGISTRY_ORG_TEAM_MAPPING.TEAM_ID=REGISTRY_TEAM_USER_MAPPING.TEAM_ID " +
	"WHERE REGISTRY_TEAM_USER_MAPPING.USER_UUID=? AND REGISTRY_ORG_TEAM_MAPPING.ORG_NAME=? " +
	"AND REGISTRY_ORG_TEAM_MAPPING.TEAM_NAME='OWNER'"
const getPermissionQuery = "SELECT RITM.PERMISSION FROM " +
	"REGISTRY_ORG_TEAM_MAPPING ROTM " +
	"INNER JOIN REGISTRY_IMAGE_TEAM_MAPPING RITM ON RITM.TEAM_ID=ROTM.TEAM_ID " +
	"INNER JOIN REGISTRY_TEAM_USER_MAPPING RTUM ON RTUM.TEAM_ID=ROTM.TEAM_ID " +
	"INNER JOIN REGISTRY_ARTIFACT_IMAGE RAI ON RAI.ARTIFACT_IMAGE_ID=RITM.ARTIFACT_IMAGE_ID " +
	"WHERE RTUM.USER_UUID=? AND ROTM.ORG_NAME=? AND RAI.IMAGE_NAME=?"
const checkImageQuery = "SELECT 1 FROM REGISTRY_ARTIFACT_IMAGE WHERE IMAGE_NAME=?"
