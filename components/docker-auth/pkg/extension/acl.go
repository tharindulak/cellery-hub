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

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/cesanta/docker_auth/auth_server/api"
	_ "github.com/go-sql-driver/mysql"
)

func ValidateAccess(db *sql.DB, actions []string, username string, repository string, labels api.Labels,
	logger *zap.SugaredLogger, execId string) (bool, error) {

	logger.Debugf("[%s] Required actions for the username are :%s", execId, actions)
	logger.Debugf("[%s] Received labels are :%s", execId, labels)

	isPullOnly := false
	isPullNDeleteAction := false
	isPushAction := false
	if len(actions) == 1 && actions[0] == pullAction {
		log.Printf("[%s] Received a request for pull only action\n", execId)
		isPullOnly = true
	} else if len(actions) == 2 {
		if actions[0] == pullAction && actions[1] == pushAction {
			log.Printf("[%s] Received a request for push action\n", execId)
			isPushAction = true
		} else if actions[0] == deleteAction && actions[1] == pullAction {
			log.Printf("[%s] Received a request for pull and delete actions\n", execId)
			isPullNDeleteAction = true
		}
	}

	logger.Debugf("[%s] Label map length : %d", execId, len(labels))
	if len(labels) < 1 {
		logger.Debugf("[%s] Not received any label", execId)
		return false, nil
	}

	if labels["isAuthSuccess"][0] == "true" {
		logger.Debugf("[%s] Validating access for authenticated user", execId)
	} else {
		if isPullOnly {
			logger.Debugf("[%s] Validating access for unauthenticated user for pull action", execId)
		} else {
			log.Printf("[%s] Denying access for unauthenticated user for push/delete actions\n", execId)
			return false, nil
		}
	}

	organization, image, err := getOrganizationAndImage(repository, logger, execId)
	if err != nil {
		return false, err
	}
	logger.Debugf("[%s] Image name is declared as :%s\n", execId, image)
	if isPullOnly {
		log.Printf("[%s] Received a pulling task\n", execId)
		return isAuthorizedToPull(db, username, organization, image, logger, execId)
	} else if isPushAction {
		log.Printf("[%s] Received a pushing task\n", execId)
		return isAuthorizedToPush(db, username, organization, image, logger, execId)
	} else if isPullNDeleteAction {
		log.Printf("[%s] Received a deleting task\n", execId)
		return isAuthorizedToDelete(db, username, organization, logger, execId)
	} else {
		log.Printf("[%s] Received an unrecognized task\n", execId)
		return false, fmt.Errorf("unrecognized task requested")
	}
}

func getOrganizationAndImage(imageFullName string, logger *zap.SugaredLogger, execId string) (string, string, error) {
	tokens := strings.Split(imageFullName, "/")
	logger.Debugf("[%s] Organization and image info: %s", execId, tokens)
	if len(tokens) == 2 {
		logger.Debugf("[%s] Organization : %s, image : %s", execId, tokens[0], tokens[1])
		return tokens[0], tokens[1], nil
	} else {
		return "", "", errors.New("organization and image info not found due to token length mismatched")
	}
}

func getImageVisibility(db *sql.DB, image string, organization string, logger *zap.SugaredLogger,
	execId string) (string, error) {
	logger.Debugf("[%s] Retrieving image visibility for image %s in organization %s", execId,
		image, organization)
	var visibility = ""
	results, err := db.Query(getVisibilityQuery, image, organization)
	defer func() {
		closeResultSet(results, "getImageVisibility", logger, execId)
	}()
	if err != nil {
		return visibility, fmt.Errorf("error while calling the mysql query getVisibilityQuery :%s", err)
	}
	if results.Next() {
		err = results.Scan(&visibility)
		logger.Debugf("[%s] Visibility of the image %s/%s is found as %s from the db", execId, organization,
			image, visibility)
	} else {
		logger.Debugf("[%s] Visibility of the image %s/%s is not found in the db", execId, organization,
			image)
	}
	if err != nil {
		return visibility, fmt.Errorf("[%s] Error in retrieving the visibility for %s/%s from the "+
			"database :%s", execId, organization, image, err)
	}
	return visibility, nil
}

func isUserAvailable(db *sql.DB, organization, user string, logger *zap.SugaredLogger, execId string) (bool, error) {
	logger.Debugf("[%s] Checking whether the user %s exists in the organization %s", execId, user,
		organization)
	results, err := db.Query(checkOwnerQuery, user, organization)
	defer func() {
		closeResultSet(results, "isUserAvailable", logger, execId)
	}()
	if err != nil {
		return false, fmt.Errorf("[%s] Error while calling the mysql query "+
			"checkOwnerQuery :%s\n", execId, err)
	}
	if results.Next() {
		logger.Debugf("[%s] User %s is available in the organization :%s", execId, user, organization)
		return true, nil
	} else {
		logger.Debugf("[%s] User %s is not available in the organization :%s", execId, user, organization)
		return false, nil
	}
}

func isAuthorizedToPull(db *sql.DB, user string, organization string, image string,
	logger *zap.SugaredLogger, execId string) (bool, error) {

	log.Printf("[%s] ACL is checking whether the user %s is authorized to pull the image %s in the "+
		" organization %s.\n", execId, user, image, organization)

	visibility, err := getImageVisibility(db, image, organization, logger, execId)

	if err != nil {
		logger.Debugf("[%s] User %s is not authorized to pull the image %s/%s.", execId, user,
			organization, image)
		return false, fmt.Errorf("error occured while geting visibility of image. User %s is not "+
			"authorized to pull the image %s/%s", user, organization, image)
	} else if strings.EqualFold(visibility, publicVisibility) {
		logger.Debugf("[%s] Visibility of the image %s/%s is public. Hence user %s is authorized to pull",
			execId, organization, image, user)
		return true, nil
	} else {
		logger.Debugf("[%s] Visibility is not public for image %s/%s to the user %s", execId, organization,
			image, user)
		// Check whether the username exists in the organization when a fresh image come and tries to push
		return isUserAvailable(db, organization, user, logger, execId)
	}
}

func isAuthorizedToPush(db *sql.DB, user string, organization string, image string,
	logger *zap.SugaredLogger, execId string) (bool, error) {

	logger.Debugf("[%s] User %s is trying to push to organization :%s. Checking whether image " +
		"exists in the database \n", execId, user, organization)
	results, err := db.Query(checkImageQuery, image)
	if err != nil {
		return false, fmt.Errorf("[%s] Error while calling the mysql query " +
			"check image query :%s", execId, err)
	}
	defer func() {
		closeResultSet(results, "isAuthorizedToPush", logger, execId)
	}()
	if results.Next() {
		logger.Debugf("[%s] Image exists in the registry. User privileges to push will be evaluated",
			execId)
		results, err := db.Query(getPermissionQuery, user, organization, image)
		var userRole string
		i := 0
		for ; results.Next() ; i++ {
			err = results.Scan(&userRole)
			if err != nil {
				return false, fmt.Errorf("[%s] Error in retrieving the username role from the "+
					"database :%s", execId, err)
			}
			userPermission, err := strconv.ParseInt(userRole, 10, 64)
			if err != nil {
				return false, fmt.Errorf("error while pasing string to int :%v", err)
			}
			if (userPermission == userAdminRole) || (userPermission == userPushRole) {
				logger.Debugf("[%s] User is allowed to push the image", execId)
				defer func() {
					closeResultSet(results, "isAuthorizedToPush", logger, execId)
				}()
				return true, nil
			}
		}
		if  i == 0 {
			results, err = db.Query(checkOwnerQuery, user, organization)
			defer func() {
				closeResultSet(results, "isAuthorizedToPush", logger, execId)
			}()
			if err != nil {
				return false, fmt.Errorf("[%s] Error while calling the mysql query " +
					"checkOwnerQuery :%s", execId, err)
			}
			if results.Next() {
				return true, nil
			}
		}
		return false, nil
	} else {
		results, err := db.Query(checkOwnerQuery, user, organization)
		defer func() {
			closeResultSet(results, "isAuthorizedToPush", logger, execId)
		}()
		if err != nil {
			return false, fmt.Errorf("[%s] Error while calling the mysql query " +
				"checkOwnerQuery :%s", execId, err)
		}
		isUserAvailable, err := isUserAvailable(db, organization, user, logger, execId)
		if err != nil{
			return false, err
		}
		if isUserAvailable {
			logger.Debugf("[%s] User: %s is member of the organization and push is allowed %s",
				execId, user, organization)
			return true, nil
		} else {
			logger.Debugf("[%s] User: %s is not a member of the organization %s", execId, user,
				organization)
			return false, nil
		}
	}
}

func isAuthorizedToDelete(db *sql.DB, user string, organization string,
	logger *zap.SugaredLogger, execId string) (bool, error) {

	log.Printf("[%s] User %s is trying to perform delete action on organization :%s\n", execId, user,
		organization)
	results, err := db.Query(getPermissionQuery, user, organization)
	defer func() {
		closeResultSet(results, "isAuthorizedToDelete", logger, execId)
	}()
	if err != nil {
		log.Printf("[%s] Error while calling the mysql query for getting the user role :%s\n", execId, err)
		return false, err
	}
	if results.Next() {
		var userRole string
		// for each row, scan the result into our tag composite object
		err = results.Scan(&userRole)
		if err != nil {
			log.Printf("[%s] Error in retrieving the user role from the database :%s\n", execId, err)
			return false, err
		}
		log.Printf("[%s] User role is declared as %s for the organization %s", execId, userRole, organization)
		userPermission, err := strconv.ParseInt(user, 10, 64)
		if err != nil {
			return false, fmt.Errorf("error while pasing string to int :%v", err)
		}
		if userPermission == userAdminRole {
			log.Printf("[%s] User is allowed to delete the image under organization %s", execId, organization)
			return true, nil
		} else {
			log.Printf("[%s] User does not have delete rights to delete images of organization %s", execId,
				organization)
			return false, err
		}
	}
	return false, nil
}

func closeResultSet(r *sql.Rows, caller string, logger *zap.SugaredLogger, execId string) {
	if r != nil {
		err := r.Close()
		if err != nil {
			logger.Errorf("[%s] error while closing result set in %s : %v", execId, caller, err)
		}
	}
}
