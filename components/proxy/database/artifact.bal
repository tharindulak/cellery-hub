// ------------------------------------------------------------------------
//
// Copyright 2019 WSO2, Inc. (http://wso2.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// ------------------------------------------------------------------------

import ballerina/io;
import ballerina/log;
import ballerina/sql;
import ballerina/system;
import ballerina/transactions;

//
// Records for holding the Cell Image information starts here
//

public type CellImage record {|
    string org;
    string name;
    string ver;
    map<string> labels;
    string[] ingresses;
    json metadata;
|};

//
// Records for holding the Cell Image information ends here
//

//
// Records representing the actual DB tables starts here
//

type RegistryOrganizationTable record {|
    string DEFAULT_IMAGE_VISIBILITY;
|};

type RegistryArtifactImageTable record {|
    string ARTIFACT_IMAGE_ID;
|};

type RegistryArtifactTable record {|
    string ARTIFACT_ID;
|};

//
// Records representing the actual DB tables ends here
//

# Save Cell Image to the Cellery Hub Database.
# This also incremenets the push count of the artifact by one.
#
# + userId - The UUID of the user trying to push the Cell Image
# + cellImage - Cell Image to be persisted
# + return - Error if any error occurred
public function saveCellImage(string userId, CellImage cellImage) returns error? {
    var imageUuid = check persistImage(userId, cellImage.org, cellImage.name);
    _ = check persistImageArtifact(userId, imageUuid, cellImage);
}

# Increment the pull count for a specific image.
#
# + orgName - Name of the organization of the image
# + imageName - Name of the image
# + imageVersion - Version of the image
# + return - Error if any occurred
public function incrementPullCount(string orgName, string imageName, string imageVersion) returns error? {
    var registryArtifactImageTable = check celleryHubDB->select(GET_ARTIFACT_IMAGE_ID_QUERY, RegistryArtifactImageTable,
        orgName, imageName, loadToMemory = true);

    if (registryArtifactImageTable.count() == 1) {
        var registryArtifactImage = check RegistryArtifactImageTable.convert(registryArtifactImageTable.getNext());
        registryArtifactImageTable.close();
        var imageUuid = registryArtifactImage.ARTIFACT_IMAGE_ID;

        _ = check celleryHubDB->update(UPDATE_PULL_COUNT_QUERY, imageUuid, imageVersion);
        log:printDebug(io:sprintf("Incremented pull count of image %s for transaction %s", imageUuid,
            transactions:getCurrentTransactionId()));
    } else {
        registryArtifactImageTable.close();
        var err = error(io:sprintf("unexpected error due to artifact image %s/%s not being available in the database",
            orgName, imageName));
        return err;
    }
}

# Persist Image in the Cellery Hub database.
#
# + userId - The UUID of the user who is pushing the image
# + orgName - Name of the organization of the Cell Image
# + imageName - Name of the Cell Image
# + return - Image registry artifcat image ID
function persistImage(string userId, string orgName, string imageName) returns (string|error) {
    var registryArtifactImageTable = check celleryHubDB->select(GET_ARTIFACT_IMAGE_ID_QUERY, RegistryArtifactImageTable,
        orgName, imageName, loadToMemory = true);

    string uuid;
    if (registryArtifactImageTable.count() == 1) {
        var registryArtifactImage = check RegistryArtifactImageTable.convert(registryArtifactImageTable.getNext());
        registryArtifactImageTable.close();
        uuid = registryArtifactImage.ARTIFACT_IMAGE_ID;
        log:printDebug(io:sprintf("Using existing image %s/%s with id %s for transaction %s", orgName, imageName, uuid,
            transactions:getCurrentTransactionId()));
    } else {
        registryArtifactImageTable.close();
        var defaultVisibility = check getOrganizationDefaultVisibility(orgName);
        uuid = system:uuid();
        _ = check celleryHubDB->update(INSERT_ARTIFACT_IMAGE_QUERY, uuid, orgName, imageName, userId,
            defaultVisibility);
        log:printDebug(io:sprintf("Created new image %s/%s with id %s and visibility %s for transaction %s", orgName,
            imageName, uuid, defaultVisibility, transactions:getCurrentTransactionId()));
    }
    return uuid;
}

# Get the organization's default image visibility.
#
# + orgName - Name of the organization
# + return - Error or organization's default visibility
function getOrganizationDefaultVisibility(string orgName) returns (error|string) {
    var organizationTable = check celleryHubDB->select(GET_ORG_DEFAULT_IMAGE_VISIBILITY_QUERY,
        RegistryOrganizationTable, orgName, loadToMemory = true);
    if (organizationTable.count() == 1) {
        var organization = check RegistryOrganizationTable.convert(organizationTable.getNext());
        organizationTable.close();
        return organization.DEFAULT_IMAGE_VISIBILITY;
    } else {
        organizationTable.close();
        var err = error(io:sprintf("unexpected error due to organization %s not being available in the database",
            orgName));
        return err;
    }
}

# Persist Image Artifact in the Cellery Hub database.
#
# + userId - The UUID of the user who is pushing the image
# + artifactImageId - ID of the Cell Image without considering the versions
# + cellImage - Cell Image to be persisted
# + return - Error if any error occurred
function persistImageArtifact(string userId, string artifactImageId, CellImage cellImage) returns error? {
    var registryArtifactTable = check celleryHubDB->select(GET_ARTIFACT_ID_QUERY, RegistryArtifactTable,
        artifactImageId, cellImage.ver, loadToMemory = true);

    var metadataString = check string.convert(cellImage.metadata);
    string artifactUuid;
    if (registryArtifactTable.count() == 1) {
        var registryArtifact = check RegistryArtifactTable.convert(registryArtifactTable.getNext());
        registryArtifactTable.close();
        artifactUuid = registryArtifact.ARTIFACT_ID;
        _ = check celleryHubDB->update(UPDATE_REGISTRY_ARTIFACT_QUERY, userId, metadataString, false, artifactUuid,
            cellImage.ver);
        log:printDebug(io:sprintf("Updated image with image id %s and version %s for transaction %s", artifactImageId,
            cellImage.ver, transactions:getCurrentTransactionId()));

        // Cleanup all existing related info tables
        _ = check cleanUpLabels(artifactUuid);
        _ = check cleanUpIngresses(artifactUuid);
    } else {
        registryArtifactTable.close();
        artifactUuid = system:uuid();
        _ = check celleryHubDB->update(INSERT_REGISTRY_ARTIFACT_QUERY, artifactUuid, artifactImageId,
            cellImage.ver, userId, userId, metadataString, false);
        log:printDebug(io:sprintf("Created new image with image id %s and version %s for transaction %s",
            artifactImageId, cellImage.ver, transactions:getCurrentTransactionId()));
    }
    _ = check persistImageArtifactLabels(artifactUuid, cellImage.labels);
    _ = check persistImageArtifactIngresses(artifactUuid, cellImage.ingresses);
}

# Cleanup labels for an artifact.
#
# + artifactId - ID of the Cell Image without considering the versions
# + return - Error if any occurred
function cleanUpLabels(string artifactId) returns error? {
    _ = check celleryHubDB->update(DELETE_REGISTRY_ARTIFACT_LABELS_QUERY, artifactId);
    log:printDebug(io:sprintf("Removed all labels for image version with artifact id %s for transaction %s", artifactId,
        transactions:getCurrentTransactionId()));
}

# Persist Image Artifact labels in the Cellery Hub database.
#
# + artifactId - ID of the Cell Image without considering the versions
# + labels - labels to be added
# + return - Error if any occurred
function persistImageArtifactLabels(string artifactId, map<string> labels) returns error? {
    if (labels.length() > 0) {
        string[][] dataBatch = [];
        int i = 0;
        foreach var (labelKey, labelValue) in labels {
            dataBatch[i] = [artifactId, labelKey, labelValue];
            i = i + 1;
        }
        _ = check celleryHubDB->batchUpdate(INSERT_REGISTRY_ARTIFACT_LABELS_QUERY, ...dataBatch);
        log:printDebug(io:sprintf("Added labels for image version with artifact id %s for transaction %s", artifactId,
            transactions:getCurrentTransactionId()));
    }
}

# Cleanup labels for an artifact.
#
# + artifactId - ID of the Cell Image
# + return - Error if any occurred
function cleanUpIngresses(string artifactId) returns error? {
    _ = check celleryHubDB->update(DELETE_REGISTRY_ARTIFACT_INGRESSES_QUERY, artifactId);
    log:printDebug(io:sprintf("Removed all ingresses for image version with artifact id %s for transaction %s",
        artifactId, transactions:getCurrentTransactionId()));
}

# Persist Image Artifact ingresses in the Cellery Hub database.
#
# + artifactId - ID of the Cell Image
# + ingresses - ingresses to be added
# + return - Error if any occurred
function persistImageArtifactIngresses(string artifactId, string[] ingresses) returns error? {
    if (ingresses.length() > 0) {
        string[][] dataBatch = [];
        int j = 0;
        foreach var ingress in ingresses {
            dataBatch[j] = [artifactId, ingress];
            j = j + 1;
        }
        _ = check celleryHubDB->batchUpdate(INSERT_REGISTRY_ARTIFACT_INGRESSES_QUERY, ...dataBatch);
        log:printDebug(
            io:sprintf("Added ingresses for image version with artifact id %s for transaction for transaction %s",
                artifactId, transactions:getCurrentTransactionId())
        );
    }
}
