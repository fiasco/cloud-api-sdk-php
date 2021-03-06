# Functions
Function | Summary
-------- | -------
[getSystemHealthStatus](#getSystemHealthStatus) | Return the current system health status.
[getAccount](#getAccount) | Returns details about your account.
[getAccountApplicationHasPermission](#getAccountApplicationHasPermission) | Returns whether your account has access to a specific application permission.
[getAccountApplicationIsAdministrator](#getAccountApplicationIsAdministrator) | Returns whether your account is an administrator for an application.
[getAccountApplicationIsOwner](#getAccountApplicationIsOwner) | Returns whether your account is the owner for an application.
[postAccountApplicationMarkRecent](#postAccountApplicationMarkRecent) | Marks an application as recently viewed.
[postAccountApplicationStar](#postAccountApplicationStar) | Stars an application.
[postAccountApplicationUnstar](#postAccountApplicationUnstar) | Removes an application from the user's starred list.
[getAccountDrushAliasesDownload](#getAccountDrushAliasesDownload) | Returns the drush aliases as a compressed archive download.
[getAccountInvites](#getAccountInvites) | Gets a list of all organization admin and team invites that are pending for the current user.
[getAccountMessages](#getAccountMessages) | Returns a list of messages associated with the current user.
[getAccountOrganizationIsAdministrator](#getAccountOrganizationIsAdministrator) | Returns whether your account is an administrator for an organization.
[getAccountOrganizationIsOwner](#getAccountOrganizationIsOwner) | Returns whether your account is the owner for an organization.
[postAccountPassword](#postAccountPassword) | Verifies that the supplied password matches the current user's password.
[getAccountSshKeys](#getAccountSshKeys) | Gets a list of SSH keys associated with the current user.
[postAccountSshKeys](#postAccountSshKeys) | Installs a new SSH key for the current user.
[getAccountSshKey](#getAccountSshKey) | Get an SSH key associated with the currently-logged in user.
[deleteAccountSshKey](#deleteAccountSshKey) | Deletes an SSH key.
[getAccountSubscriptionIsAdministrator](#getAccountSubscriptionIsAdministrator) | Returns whether your account is an administrator for a subscription.
[getAccountSubscriptionIsOwner](#getAccountSubscriptionIsOwner) | Returns whether your account is the owner for a subscription.
[getAccountTeamHasPermission](#getAccountTeamHasPermission) | Returns whether your account has access to a specific team permission.
[getAccountTeamIsAdministrator](#getAccountTeamIsAdministrator) | Returns whether your account is an administrator for a team.
[getAccountTeamIsOwner](#getAccountTeamIsOwner) | Returns whether your account is the owner for a team.
[getAccountTokens](#getAccountTokens) | Returns a list of metadata for API access tokens tied to your account.
[postAccountTokens](#postAccountTokens) | Creates an API access token tied to your account.
[getAccountToken](#getAccountToken) | Return details about a specific token.
[deleteAccountToken](#deleteAccountToken) | Revokes an access token.
[getAgreements](#getAgreements) | Return a list of agreements.
[getAgreement](#getAgreement) | Return a specific agreement by a provided UUID.
[postAcceptAgreement](#postAcceptAgreement) | Accepts a legal agreement by UUID.
[postDeclineAgreement](#postDeclineAgreement) | Declines a legal agreement by UUID.
[getInvitees](#getInvitees) | Returns a list of users invited to action this agreement.
[getApplications](#getApplications) | Return a list of applications the current user has access to.
[getApplicationByUuid](#getApplicationByUuid) | Return details about a specific application.
[putApplicationByUuid](#putApplicationByUuid) | Renames an application.
[getArtifactsByApplicationUuid](#getArtifactsByApplicationUuid) | Return application artifacts.
[getArtifactByApplicationUuidAndId](#getArtifactByApplicationUuidAndId) | Return details about a specific artifact.
[getCodeByApplicationUuid](#getCodeByApplicationUuid) | Return application branches and release tags.
[getApplicationDatabases](#getApplicationDatabases) | Returns a list database names for the application.
[postApplicationDatabaseCreate](#postApplicationDatabaseCreate) | Creates a database.
[postApplicationDatabaseDelete](#postApplicationDatabaseDelete) | Drops (deletes) a database.
[postApplicationDatabaseErase](#postApplicationDatabaseErase) | Erases (truncates) a database.
[getApplicationIdes](#getApplicationIdes) | Returns a list of Remote IDEs associated with this application.
[postApplicationsIde](#postApplicationsIde) | Creates a new Remote IDE.
[getApplicationMessages](#getApplicationMessages) | Returns a list of messages associated with this application.
[getApplicationNotifications](#getApplicationNotifications) | Returns a list of notifications associated with this application by its UUID.
[getApplicationNotificationByUuid](#getApplicationNotificationByUuid) | Returns a single notification.
[getApplicationPermissions](#getApplicationPermissions) | Returns a list of permissions the user has for this application by its UUID.
[getApplicationSettings](#getApplicationSettings) | Returns available settings for this application.
[getApplicationHostingSettings](#getApplicationHostingSettings) | Returns the hosting settings for this application.
[getApplicationLegacyProductKeysSettings](#getApplicationLegacyProductKeysSettings) | Returns the legacy product keys for this application.
[getApplicationRemoteAdministrationSettings](#getApplicationRemoteAdministrationSettings) | Returns the remote administration settings for this application.
[putApplicationRemoteAdministrationSettings](#putApplicationRemoteAdministrationSettings) | Modifies the remote administration settings for an application.
[getApplicationSearchSettings](#getApplicationSearchSettings) | Returns the search settings for this application.
[putApplicationSearchSettings](#putApplicationSearchSettings) | Modifies the search settings for an application.
[getApplicationSecuritySettings](#getApplicationSecuritySettings) | Returns the security policy settings for this application.
[putApplicationSecuritySettings](#putApplicationSecuritySettings) | Modifies the security policy settings for an application.
[getApplicationTags](#getApplicationTags) | Returns a list of application tags associated with this application.
[postApplicationsTags](#postApplicationsTags) | Creates a new application tag.
[deleteApplicationTags](#deleteApplicationTags) | Deletes an application tag.
[getApplicationTasks](#getApplicationTasks) | Returns a list of tasks associated with this application by its UUID.
[getApplicationTeams](#getApplicationTeams) | Returns a list of teams associated with this application.
[getApplicationsUsageLinks](#getApplicationsUsageLinks) | Retrieves traversal links for an application's usage data.
[getApplicationsUsageData](#getApplicationsUsageData) | Retrieves aggregate usage data for an application.
[getApplicationsUsageDataByEnvironment](#getApplicationsUsageDataByEnvironment) | Retrieves usage data for an application, broken down by environment.
[getApplicationsUsageMetricData](#getApplicationsUsageMetricData) | Retrieves aggregate usage metric data for an application.
[getApplicationsUsageViewsDataByEnvironment](#getApplicationsUsageViewsDataByEnvironment) | Retrieves views data for an application, broken down by environment.
[getApplicationsUsageVisitsDataByEnvironment](#getApplicationsUsageVisitsDataByEnvironment) | Retrieves visits data for an application, broken down by environment.
[getDistributions](#getDistributions) | Return a list of Drupal distributions.
[getDistributionByName](#getDistributionByName) | Return details about a specific Drupal distribution.
[getApplicationEnvironments](#getApplicationEnvironments) | Returns a list of environments within this application by its UUID.
[postApplicationEnvironments](#postApplicationEnvironments) | Add a new continuous delivery environment to an application by the application UUID.
[getApplicationFeatures](#getApplicationFeatures) | Return application features.
[getInsightDataBySites](#getInsightDataBySites) | Returns Insight data for all sites associated with the application by its UUID.
[getEnvironment](#getEnvironment) | Return details about a specific environment.
[putEnvironment](#putEnvironment) | Modifies configuration settings for an environment.
[deleteEnvironment](#deleteEnvironment) | Deletes a CD environment.
[postChangeEnvironmentLabel](#postChangeEnvironmentLabel) | Change the label for an environment.
[postResizeEnvironment](#postResizeEnvironment) | Resize an environment.
[postDeployArtifact](#postDeployArtifact) | Deploys an artifact to this environment.
[getAvailableRuntimes](#getAvailableRuntimes) | Return a list of runtimes.
[postEnvironmentsDeployCode](#postEnvironmentsDeployCode) | Deploys code to this environment.
[postEnvironmentsSwitchCode](#postEnvironmentsSwitchCode) | Switches code on this environment to a different branch or release tag.
[postEnvironmentsImportSite](#postEnvironmentsImportSite) | Imports a site to this environment.
[getCronJobsByEnvironmentId](#getCronJobsByEnvironmentId) | Return environment cron jobs.
[postEnvironmentCrons](#postEnvironmentCrons) | Creates a scheduled job with cron.
[getCron](#getCron) | Return details about a specific cron job.
[putCron](#putCron) | Modify an existing scheduled job.
[postEnvironmentCronDelete](#postEnvironmentCronDelete) | Deletes a cron job.
[postEnvironmentCronEnable](#postEnvironmentCronEnable) | Enables a cron job.
[postEnvironmentCronDisable](#postEnvironmentCronDisable) | Disables a cron job.
[getEnvironmentsDatabases](#getEnvironmentsDatabases) | Returns a list of databases.
[postEnvironmentsDatabases](#postEnvironmentsDatabases) | Copies a database to this environment.
[getEnvironmentsDatabase](#getEnvironmentsDatabase) | Return details about a specific database.
[getEnvironmentsDatabasePhpConfig](#getEnvironmentsDatabasePhpConfig) | Returns PHP configuration details for this database.
[getEnvironmentsDatabaseBackups](#getEnvironmentsDatabaseBackups) | Returns a list of backups.
[postEnvironmentsDatabaseBackups](#postEnvironmentsDatabaseBackups) | Create a backup.
[getEnvironmentsDatabaseBackup](#getEnvironmentsDatabaseBackup) | Return details about a specific backup.
[deleteEnvironmentsDatabaseBackup](#deleteEnvironmentsDatabaseBackup) | Deletes a database backup.
[getEnvironmentsDatabaseDownloadBackup](#getEnvironmentsDatabaseDownloadBackup) | Downloads the database backup file.
[postEnvironmentsDatabaseRestoreBackup](#postEnvironmentsDatabaseRestoreBackup) | Restores this backup to the appropriate environment's database.
[getEnvironmentsDns](#getEnvironmentsDns) | Returns DNS configuration details for an environment.
[getEnvironmentsDomains](#getEnvironmentsDomains) | Returns a list of domains.
[postEnvironmentsDomains](#postEnvironmentsDomains) | Adds a domain to the environment.
[postEnvironmentsDomainsClearVarnish](#postEnvironmentsDomainsClearVarnish) | Clears the Varnish cache for one or more domains attached to this environment.
[getEnvironmentsDomain](#getEnvironmentsDomain) | Return details about a specific domain.
[deleteEnvironmentsDomain](#deleteEnvironmentsDomain) | Removes the domain from this environment.
[postEnvironmentsDomainClearVarnish](#postEnvironmentsDomainClearVarnish) | Clears the Varnish cache for the specified domain.
[getEnvironmentsDomainsUptimeScans](#getEnvironmentsDomainsUptimeScans) | Retrieves Uptime scan data for a specific domain.
[getEnvironmentsDomainStatus](#getEnvironmentsDomainStatus) | Returns details about the domain.
[postEnvironmentsFiles](#postEnvironmentsFiles) | Copies files to this environment.
[getInsightForEnvironment](#getInsightForEnvironment) | Returns insight data.
[getEnvironmentsLogs](#getEnvironmentsLogs) | Returns a list of log files for this environment available for download.
[getEnvironmentsLog](#getEnvironmentsLog) | Downloads the log file.
[postEnvironmentsLog](#postEnvironmentsLog) | Creates a log file snapshot.
[getEnvironmentsLogstream](#getEnvironmentsLogstream) | Returns a logstream url and metadata.
[postEnvironmentsDisableLiveDev](#postEnvironmentsDisableLiveDev) | Disable Live Development on this environment.
[postEnvironmentsEnableLiveDev](#postEnvironmentsEnableLiveDev) | Enable Live Development on this environment.
[getEnvironmentsLogForwardingDestinations](#getEnvironmentsLogForwardingDestinations) | Returns a collection of log forwarding destinations for this environment.
[postEnvironmentsLogForwardingDestinations](#postEnvironmentsLogForwardingDestinations) | Creates a log forwarding destination.
[getEnvironmentsLogForwardingDestination](#getEnvironmentsLogForwardingDestination) | Returns the specified log forwarding destination.
[putEnvironmentsLogForwardingDestination](#putEnvironmentsLogForwardingDestination) | Updates an environment's log forwarding destination.
[deleteEnvironmentsLogForwardingDestination](#deleteEnvironmentsLogForwardingDestination) | Deletes the specified log forwarding destination.
[postEnvironmentsDisableLogForwardingDestination](#postEnvironmentsDisableLogForwardingDestination) | Disables the specified log forwarding destination.
[postEnvironmentsEnableLogForwardingDestination](#postEnvironmentsEnableLogForwardingDestination) | Enables the specified log forwarding destination.
[getEnvironmentsMetrics](#getEnvironmentsMetrics) | Does not return any data. Allows traversal to metrics groups endpoints.
[getEnvironmentsStackMetrics](#getEnvironmentsStackMetrics) | Does not return any data. Allows traversal to StackMetrics endpoints.
[getEnvironmentsStackMetricsData](#getEnvironmentsStackMetricsData) | Returns StackMetrics data for the metrics specified in the filter paramater (e.g., apache-access, web-cpu).
[getEnvironmentsStackMetricsMetric](#getEnvironmentsStackMetricsMetric) | Returns StackMetrics data for the metric (e.g., apache-access).
[getEnvironmentsUsageLinks](#getEnvironmentsUsageLinks) | Retrieves traversal links for an environment's usage data.
[getEnvironmentsUsageData](#getEnvironmentsUsageData) | Retrieves usage data for an environment.
[getEnvironmentsUsageMetricData](#getEnvironmentsUsageMetricData) | Retrieves usage metric data for an environment.
[postEnvironmentsDisableProductionMode](#postEnvironmentsDisableProductionMode) | Disables production mode for an environment.
[postEnvironmentsEnableProductionMode](#postEnvironmentsEnableProductionMode) | Enables production mode for an environment.
[getEnvironmentsServers](#getEnvironmentsServers) | Returns a list of servers.
[getEnvironmentsServer](#getEnvironmentsServer) | Return details about a specific server.
[putEnvironmentsServer](#putEnvironmentsServer) | Modifies configuration settings for a server.
[postEnvironmentsServerReboot](#postEnvironmentsServerReboot) | Reboots a server.
[postEnvironmentsServerRelaunch](#postEnvironmentsServerRelaunch) | Relaunches a server.
[postEnvironmentsServerSuspend](#postEnvironmentsServerSuspend) | Suspends a server.
[postEnvironmentsServerUpgrade](#postEnvironmentsServerUpgrade) | Upgrades a server from "precise" to "xenial".
[getEnvironmentsSettings](#getEnvironmentsSettings) | Provides links to environment settings.
[getEnvironmentsApmSetting](#getEnvironmentsApmSetting) | Return details about a specific APM.
[putEnvironmentsApmSetting](#putEnvironmentsApmSetting) | Update configuration for an APM tool.
[getSsl](#getSsl) | Returns the SSL settings for this environment.
[getCertificates](#getCertificates) | Return a list of SSL certificates.
[postCertificate](#postCertificate) | Install an SSL certificate.
[getCertificate](#getCertificate) | Returns a specific certificate by certificate id.
[deleteCertificate](#deleteCertificate) | Deletes a specific certificate by its ID.
[postActivateCertificate](#postActivateCertificate) | Activates an SSL certificate.
[postDeactivateCertificate](#postDeactivateCertificate) | Deactivates an active SSL certificate.
[getCertificateSigningRequests](#getCertificateSigningRequests) | Returns certificate signing requests.
[postCertificateSigningRequest](#postCertificateSigningRequest) | Generates a CSR for one or more domains.
[getCertificateSigningRequest](#getCertificateSigningRequest) | Returns the certificate signing request for the certificate specified by id.
[deleteCertificateSigningRequest](#deleteCertificateSigningRequest) | Deletes the certificate signing request.
[getEnvironmentsVariables](#getEnvironmentsVariables) | Returns a list of environment variables associated with this environment.
[postEnvironmentsVariables](#postEnvironmentsVariables) | Adds a new environment variable to an environment.
[getEnvironmentsVariable](#getEnvironmentsVariable) | Get an environment variable associated with this environment.
[deleteEnvironmentsVariable](#deleteEnvironmentsVariable) | Removes an environment variable from an environment.
[putEnvironmentsVariable](#putEnvironmentsVariable) | Updates an environment variable on an environment.
[getIde](#getIde) | Returns Remote IDE info.
[deleteIde](#deleteIde) | De-provisions a specific Remote IDE.
[getIdentityProviders](#getIdentityProviders) | Returns a list of identity providers for a user.
[getIdentityProvider](#getIdentityProvider) | Returns a specific identity provider by UUID.
[putIdentityProvider](#putIdentityProvider) | Modifies an identity provider by its UUID.
[deleteIdentityProvider](#deleteIdentityProvider) | Deletes a specific identity provider by its UUID.
[postEnableIdentityProvider](#postEnableIdentityProvider) | Enables an identity provider by its UUID.
[postDisableIdentityProvider](#postDisableIdentityProvider) | Disables an identity provider by its UUID.
[findInsightDataBySiteId](#findInsightDataBySiteId) | Returns insight data for a particular site.
[postRevokeInsight](#postRevokeInsight) | Revokes an Insight install so it can no longer submit data using the Acquia Connector module.
[postUnrevokeInsight](#postUnrevokeInsight) | Un-revokes an Insight site so it can once again submit data using the Acquia Connector module. Note that the site must also be unblocked using the Acquia Connector module.
[getFindInsightAlertsForSite](#getFindInsightAlertsForSite) | Returns a list of Insight alerts for this site.
[getInsightByUuid](#getInsightByUuid) | Returns a specific Insight alert for this site.
[postIgnoreInsightAlert](#postIgnoreInsightAlert) | Ignores an alert. An ignored alert will not be counted in the Insight score calculation.
[postRestoreInsightAlert](#postRestoreInsightAlert) | Restores an alert. A restored alert will be included in the calculation of the Insight score.
[getConnectionHistoryForSite](#getConnectionHistoryForSite) | Returns a list of historical Insight connections for this site.
[getDrupalModulesForSite](#getDrupalModulesForSite) | Returns a list of Drupal modules for this site.
[getScoreHistoryForSite](#getScoreHistoryForSite) | Returns a list of historical Insight scores for this site.
[getInviteByToken](#getInviteByToken) | Returns details about an invitation.
[postInviteCancel](#postInviteCancel) | Cancels an invitation.
[postInviteAcceptByToken](#postInviteAcceptByToken) | Accepts an invite.
[postInviteDecline](#postInviteDecline) | Declines an invite.
[postInviteResend](#postInviteResend) | Resend an invite.
[postDismissMessage](#postDismissMessage) | Dismisses a message.
[getMessageFollow](#getMessageFollow) | Follows an in-product message link.
[getNotificationByUuid](#getNotificationByUuid) | Returns a single notification.
[getOptions](#getOptions) | Does not return any data. Allows traversal of options groups endpoints.
[getCdeSizes](#getCdeSizes) | Displays the various CD Environment size options.
[getLogForwarding](#getLogForwarding) | Does not return any data. Allows traversal of options groups endpoints.
[getLogForwardingSources](#getLogForwardingSources) | Displays available log forwarding sources.
[getLogForwardingConsumers](#getLogForwardingConsumers) | Displays available log forwarding consumers.
[getColors](#getColors) | Displays the various color options.
[getOrganizations](#getOrganizations) | Return a list of organizations.
[postOrganizationsCreate](#postOrganizationsCreate) | Creates a new organization.
[getOrganizationByUuid](#getOrganizationByUuid) | Return details about a specific organization.
[putOrganization](#putOrganization) | Renames an organization.
[deleteOrganization](#deleteOrganization) | Deletes a specific organization by its UUID.
[postChangeOrganizationOwner](#postChangeOrganizationOwner) | Changes the organization owner.
[postLeaveOrganization](#postLeaveOrganization) | Removes your account from an organization.
[getOrganizationAdmins](#getOrganizationAdmins) | Returns a list of organization administrators.
[getOrganizationAdmin](#getOrganizationAdmin) | Returns the user profile of this organization administrator.
[deleteOrganizationAdmin](#deleteOrganizationAdmin) | Removes the user from the list of administrators for the organization.
[getOrganizationAdminInvites](#getOrganizationAdminInvites) | Gets a list of invitations of administrators for this organization.
[postOrganizationAdminInvite](#postOrganizationAdminInvite) | Invites a user to be an administrator in this organization.
[getOrganizationApplications](#getOrganizationApplications) | Returns a list of applications that belong to the organization.
[getOrganizationAvailableTags](#getOrganizationAvailableTags) | Returns a list of all available application tags.
[getOrganizationIdentityProvider](#getOrganizationIdentityProvider) | Returns an identity provider for an organization.
[getOrganizationMembers](#getOrganizationMembers) | Returns a list of all organization members.
[getOrganizationMember](#getOrganizationMember) | Returns the user profile of this organization member.
[postOrganizationMemberDelete](#postOrganizationMemberDelete) | Removes the member from the organization.
[getOrganizationMemberApplications](#getOrganizationMemberApplications) | Returns a list of applications that an organization member has access to.
[getOrganizationRoles](#getOrganizationRoles) | Returns a list of all the canonical roles within the organization.
[postOrganizationRoles](#postOrganizationRoles) | Creates a role.
[getOrganizationSubscriptions](#getOrganizationSubscriptions) | Returns a list of subscriptions that belong to the organization.
[getOrganizationTeamInvites](#getOrganizationTeamInvites) | Gets a list of member invitations for all teams in this organization.
[getOrganizationTeams](#getOrganizationTeams) | Returns a list of teams associated with the organization.
[postOrganizationTeams](#postOrganizationTeams) | Creates a team.
[getPermissions](#getPermissions) | Return a list of permissions.
[getRole](#getRole) | Return details about a specific role.
[deleteRole](#deleteRole) | Deletes a specific role by its UUID.
[putRoleByUuid](#putRoleByUuid) | Updates a role.
[getSubscriptions](#getSubscriptions) | Return a list of subscription.
[getSubscription](#getSubscription) | Return details about a specific subscription.
[putSubscription](#putSubscription) | Modifies a subscription.
[getSubscriptionApplications](#getSubscriptionApplications) | Provides a list of applications that are a part of the subscription.
[getSubscriptionEntitlements](#getSubscriptionEntitlements) | Provides a list of entitlements that are a part of the subscription.
[getSubscriptionIdes](#getSubscriptionIdes) | Returns a list of Remote IDEs associated with this subscription.
[getSubscriptionsUsageLinks](#getSubscriptionsUsageLinks) | Retrieves traversal links for a subscription's usage data.
[getSubscriptionsUsageData](#getSubscriptionsUsageData) | Retrieves aggregate usage data for a subscription.
[getSubscriptionsUsageDataByApplication](#getSubscriptionsUsageDataByApplication) | Retrieves usage data for a subscription, broken down by application.
[getSubscriptionsUsageMetricData](#getSubscriptionsUsageMetricData) | Retrieves aggregate usage metric data for a subscription.
[getSubscriptionsUsageViewsDataByApplication](#getSubscriptionsUsageViewsDataByApplication) | Retrieves views data for a subscription, broken down by application.
[getSubscriptionsUsageVisitsDataByApplication](#getSubscriptionsUsageVisitsDataByApplication) | Retrieves visits data for a subscription, broken down by application.
[getShieldAcl](#getShieldAcl) | Provides a list of Shield ACL rules.
[postShieldAcl](#postShieldAcl) | Creates a Shield ACL rule.
[getShieldAclRuleByUuid](#getShieldAclRuleByUuid) | Returns the specified Shield ACL rule.
[putShieldAcl](#putShieldAcl) | Updates a Shield ACL rule.
[deleteShieldAcl](#deleteShieldAcl) | Deletes a Shield ACL rule.
[postResetShieldAcl](#postResetShieldAcl) | Resets Shield ACL rules to default settings.
[getTeams](#getTeams) | Return teams the current user has access to.
[getTeam](#getTeam) | Return details about a specific team.
[putTeamsName](#putTeamsName) | Change the name of a team.
[deleteTeam](#deleteTeam) | Deletes a specific team by its UUID.
[postLeaveTeam](#postLeaveTeam) | Removes the current user from a team.
[getTeamApplications](#getTeamApplications) | Returns a list of applications this team has access to.
[postTeamAddApplication](#postTeamAddApplication) | Adds an application to this team.
[deleteTeamsRemoveApplication](#deleteTeamsRemoveApplication) | Removes the application from this team.
[getTeamInvites](#getTeamInvites) | Returns a list of invitations to this team.
[postTeamsInviteUser](#postTeamsInviteUser) | Invites a user to join a team.
[getTeamMembers](#getTeamMembers) | Returns a list of team members.
[putTeamsMember](#putTeamsMember) | Grant team roles to a member.
[deleteTeamsRemoveMember](#deleteTeamsRemoveMember) | Remove a user from a team.


## getSystemHealthStatus

Return the current system health status.
```php
$response = $client->getSystemHealthStatus();
```


## getAccount

Returns details about your account.
```php
$response = $client->getAccount();
```


## getAccountApplicationHasPermission

Returns whether your account has access to a specific application permission.
```php
$response = $client->getAccountApplicationHasPermission([
	'ApplicationUuid' => $ApplicationUuid,
	'Permission' => $Permission
]);
```


## getAccountApplicationIsAdministrator

Returns whether your account is an administrator for an application.
```php
$response = $client->getAccountApplicationIsAdministrator([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getAccountApplicationIsOwner

Returns whether your account is the owner for an application.
```php
$response = $client->getAccountApplicationIsOwner([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## postAccountApplicationMarkRecent

Marks an application as recently viewed.
```php
$response = $client->postAccountApplicationMarkRecent([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## postAccountApplicationStar

Stars an application.
```php
$response = $client->postAccountApplicationStar([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## postAccountApplicationUnstar

Removes an application from the user's starred list.
```php
$response = $client->postAccountApplicationUnstar([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getAccountDrushAliasesDownload

Returns the drush aliases as a compressed archive download.
```php
$response = $client->getAccountDrushAliasesDownload([
	'DrushVersion' => $DrushVersion
]);
```


## getAccountInvites

Gets a list of all organization admin and team invites that are pending for the current user.
```php
$response = $client->getAccountInvites([
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getAccountMessages

Returns a list of messages associated with the current user.
```php
$response = $client->getAccountMessages([
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getAccountOrganizationIsAdministrator

Returns whether your account is an administrator for an organization.
```php
$response = $client->getAccountOrganizationIsAdministrator([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## getAccountOrganizationIsOwner

Returns whether your account is the owner for an organization.
```php
$response = $client->getAccountOrganizationIsOwner([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## postAccountPassword

Verifies that the supplied password matches the current user's password.
```php
$response = $client->postAccountPassword();
```


## getAccountSshKeys

Gets a list of SSH keys associated with the current user.
```php
$response = $client->getAccountSshKeys([
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postAccountSshKeys

Installs a new SSH key for the current user.
```php
$response = $client->postAccountSshKeys();
```


## getAccountSshKey

Get an SSH key associated with the currently-logged in user.
```php
$response = $client->getAccountSshKey([
	'SshKeyUuid' => $SshKeyUuid
]);
```


## deleteAccountSshKey

Deletes an SSH key.
```php
$response = $client->deleteAccountSshKey([
	'SshKeyUuid' => $SshKeyUuid
]);
```


## getAccountSubscriptionIsAdministrator

Returns whether your account is an administrator for a subscription.
```php
$response = $client->getAccountSubscriptionIsAdministrator([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## getAccountSubscriptionIsOwner

Returns whether your account is the owner for a subscription.
```php
$response = $client->getAccountSubscriptionIsOwner([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## getAccountTeamHasPermission

Returns whether your account has access to a specific team permission.
```php
$response = $client->getAccountTeamHasPermission([
	'TeamUuid' => $TeamUuid,
	'Permission' => $Permission
]);
```


## getAccountTeamIsAdministrator

Returns whether your account is an administrator for a team.
```php
$response = $client->getAccountTeamIsAdministrator([
	'TeamUuid' => $TeamUuid
]);
```


## getAccountTeamIsOwner

Returns whether your account is the owner for a team.
```php
$response = $client->getAccountTeamIsOwner([
	'TeamUuid' => $TeamUuid
]);
```


## getAccountTokens

Returns a list of metadata for API access tokens tied to your account.
```php
$response = $client->getAccountTokens();
```


## postAccountTokens

Creates an API access token tied to your account.
```php
$response = $client->postAccountTokens();
```


## getAccountToken

Return details about a specific token.
```php
$response = $client->getAccountToken([
	'TokenUuid' => $TokenUuid
]);
```


## deleteAccountToken

Revokes an access token.
```php
$response = $client->deleteAccountToken([
	'TokenUuid' => $TokenUuid,
	'TokenDeleteReason' => $TokenDeleteReason
]);
```


## getAgreements

Return a list of agreements.
```php
$response = $client->getAgreements();
```


## getAgreement

Return a specific agreement by a provided UUID.
```php
$response = $client->getAgreement([
	'AgreementUuid' => $AgreementUuid
]);
```


## postAcceptAgreement

Accepts a legal agreement by UUID.
```php
$response = $client->postAcceptAgreement([
	'AgreementUuid' => $AgreementUuid
]);
```


## postDeclineAgreement

Declines a legal agreement by UUID.
```php
$response = $client->postDeclineAgreement([
	'AgreementUuid' => $AgreementUuid
]);
```


## getInvitees

Returns a list of users invited to action this agreement.
```php
$response = $client->getInvitees([
	'AgreementUuid' => $AgreementUuid
]);
```


## getApplications

Return a list of applications the current user has access to.
```php
$response = $client->getApplications([
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getApplicationByUuid

Return details about a specific application.
```php
$response = $client->getApplicationByUuid([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## putApplicationByUuid

Renames an application.
```php
$response = $client->putApplicationByUuid([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getArtifactsByApplicationUuid

Return application artifacts.
```php
$response = $client->getArtifactsByApplicationUuid([
	'ApplicationUuid' => $ApplicationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getArtifactByApplicationUuidAndId

Return details about a specific artifact.
```php
$response = $client->getArtifactByApplicationUuidAndId([
	'ApplicationUuid' => $ApplicationUuid,
	'ArtifactId' => $ArtifactId
]);
```


## getCodeByApplicationUuid

Return application branches and release tags.
```php
$response = $client->getCodeByApplicationUuid([
	'ApplicationUuid' => $ApplicationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter
]);
```


## getApplicationDatabases

Returns a list database names for the application.
```php
$response = $client->getApplicationDatabases([
	'ApplicationUuid' => $ApplicationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postApplicationDatabaseCreate

Creates a database.
```php
$response = $client->postApplicationDatabaseCreate([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## postApplicationDatabaseDelete

Drops (deletes) a database.
```php
$response = $client->postApplicationDatabaseDelete([
	'ApplicationUuid' => $ApplicationUuid,
	'Name' => $Name
]);
```


## postApplicationDatabaseErase

Erases (truncates) a database.
```php
$response = $client->postApplicationDatabaseErase([
	'ApplicationUuid' => $ApplicationUuid,
	'Name' => $Name
]);
```


## getApplicationIdes

Returns a list of Remote IDEs associated with this application.
```php
$response = $client->getApplicationIdes([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## postApplicationsIde

Creates a new Remote IDE.
```php
$response = $client->postApplicationsIde([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationMessages

Returns a list of messages associated with this application.
```php
$response = $client->getApplicationMessages([
	'ApplicationUuid' => $ApplicationUuid,
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getApplicationNotifications

Returns a list of notifications associated with this application by its UUID.
```php
$response = $client->getApplicationNotifications([
	'ApplicationUuid' => $ApplicationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getApplicationNotificationByUuid

Returns a single notification.
```php
$response = $client->getApplicationNotificationByUuid([
	'ApplicationUuid' => $ApplicationUuid,
	'NotificationUuid' => $NotificationUuid
]);
```


## getApplicationPermissions

Returns a list of permissions the user has for this application by its UUID.
```php
$response = $client->getApplicationPermissions([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationSettings

Returns available settings for this application.
```php
$response = $client->getApplicationSettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationHostingSettings

Returns the hosting settings for this application.
```php
$response = $client->getApplicationHostingSettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationLegacyProductKeysSettings

Returns the legacy product keys for this application.
```php
$response = $client->getApplicationLegacyProductKeysSettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationRemoteAdministrationSettings

Returns the remote administration settings for this application.
```php
$response = $client->getApplicationRemoteAdministrationSettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## putApplicationRemoteAdministrationSettings

Modifies the remote administration settings for an application.
```php
$response = $client->putApplicationRemoteAdministrationSettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationSearchSettings

Returns the search settings for this application.
```php
$response = $client->getApplicationSearchSettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## putApplicationSearchSettings

Modifies the search settings for an application.
```php
$response = $client->putApplicationSearchSettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationSecuritySettings

Returns the security policy settings for this application.
```php
$response = $client->getApplicationSecuritySettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## putApplicationSecuritySettings

Modifies the security policy settings for an application.
```php
$response = $client->putApplicationSecuritySettings([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationTags

Returns a list of application tags associated with this application.
```php
$response = $client->getApplicationTags([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## postApplicationsTags

Creates a new application tag.
```php
$response = $client->postApplicationsTags([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## deleteApplicationTags

Deletes an application tag.
```php
$response = $client->deleteApplicationTags([
	'ApplicationUuid' => $ApplicationUuid,
	'TagName' => $TagName
]);
```


## getApplicationTasks

Returns a list of tasks associated with this application by its UUID.
```php
$response = $client->getApplicationTasks([
	'ApplicationUuid' => $ApplicationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getApplicationTeams

Returns a list of teams associated with this application.
```php
$response = $client->getApplicationTeams([
	'ApplicationUuid' => $ApplicationUuid,
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getApplicationsUsageLinks

Retrieves traversal links for an application's usage data.
```php
$response = $client->getApplicationsUsageLinks([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationsUsageData

Retrieves aggregate usage data for an application.
```php
$response = $client->getApplicationsUsageData([
	'ApplicationUuid' => $ApplicationUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getApplicationsUsageDataByEnvironment

Retrieves usage data for an application, broken down by environment.
```php
$response = $client->getApplicationsUsageDataByEnvironment([
	'ApplicationUuid' => $ApplicationUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getApplicationsUsageMetricData

Retrieves aggregate usage metric data for an application.
```php
$response = $client->getApplicationsUsageMetricData([
	'UsageMetric' => $UsageMetric,
	'ApplicationUuid' => $ApplicationUuid,
	'From' => $From,
	'To' => $To
]);
```


## getApplicationsUsageViewsDataByEnvironment

Retrieves views data for an application, broken down by environment.
```php
$response = $client->getApplicationsUsageViewsDataByEnvironment([
	'ApplicationUuid' => $ApplicationUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getApplicationsUsageVisitsDataByEnvironment

Retrieves visits data for an application, broken down by environment.
```php
$response = $client->getApplicationsUsageVisitsDataByEnvironment([
	'ApplicationUuid' => $ApplicationUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getDistributions

Return a list of Drupal distributions.
```php
$response = $client->getDistributions();
```


## getDistributionByName

Return details about a specific Drupal distribution.
```php
$response = $client->getDistributionByName([
	'Name' => $Name
]);
```


## getApplicationEnvironments

Returns a list of environments within this application by its UUID.
```php
$response = $client->getApplicationEnvironments([
	'ApplicationUuid' => $ApplicationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postApplicationEnvironments

Add a new continuous delivery environment to an application by the application UUID.
```php
$response = $client->postApplicationEnvironments([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getApplicationFeatures

Return application features.
```php
$response = $client->getApplicationFeatures([
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getInsightDataBySites

Returns Insight data for all sites associated with the application by its UUID.
```php
$response = $client->getInsightDataBySites([
	'ApplicationUuid' => $ApplicationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getEnvironment

Return details about a specific environment.
```php
$response = $client->getEnvironment([
	'EnvironmentId' => $EnvironmentId
]);
```


## putEnvironment

Modifies configuration settings for an environment.
```php
$response = $client->putEnvironment([
	'EnvironmentId' => $EnvironmentId
]);
```


## deleteEnvironment

Deletes a CD environment.
```php
$response = $client->deleteEnvironment([
	'EnvironmentId' => $EnvironmentId
]);
```


## postChangeEnvironmentLabel

Change the label for an environment.
```php
$response = $client->postChangeEnvironmentLabel([
	'EnvironmentId' => $EnvironmentId
]);
```


## postResizeEnvironment

Resize an environment.
```php
$response = $client->postResizeEnvironment([
	'EnvironmentId' => $EnvironmentId
]);
```


## postDeployArtifact

Deploys an artifact to this environment.
```php
$response = $client->postDeployArtifact([
	'EnvironmentId' => $EnvironmentId
]);
```


## getAvailableRuntimes

Return a list of runtimes.
```php
$response = $client->getAvailableRuntimes([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentsDeployCode

Deploys code to this environment.
```php
$response = $client->postEnvironmentsDeployCode([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentsSwitchCode

Switches code on this environment to a different branch or release tag.
```php
$response = $client->postEnvironmentsSwitchCode([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentsImportSite

Imports a site to this environment.
```php
$response = $client->postEnvironmentsImportSite([
	'EnvironmentId' => $EnvironmentId
]);
```


## getCronJobsByEnvironmentId

Return environment cron jobs.
```php
$response = $client->getCronJobsByEnvironmentId([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentCrons

Creates a scheduled job with cron.
```php
$response = $client->postEnvironmentCrons([
	'EnvironmentId' => $EnvironmentId
]);
```


## getCron

Return details about a specific cron job.
```php
$response = $client->getCron([
	'EnvironmentId' => $EnvironmentId,
	'CronId' => $CronId
]);
```


## putCron

Modify an existing scheduled job.
```php
$response = $client->putCron([
	'EnvironmentId' => $EnvironmentId,
	'CronId' => $CronId
]);
```


## postEnvironmentCronDelete

Deletes a cron job.
```php
$response = $client->postEnvironmentCronDelete([
	'EnvironmentId' => $EnvironmentId,
	'CronId' => $CronId
]);
```


## postEnvironmentCronEnable

Enables a cron job.
```php
$response = $client->postEnvironmentCronEnable([
	'EnvironmentId' => $EnvironmentId,
	'CronId' => $CronId
]);
```


## postEnvironmentCronDisable

Disables a cron job.
```php
$response = $client->postEnvironmentCronDisable([
	'EnvironmentId' => $EnvironmentId,
	'CronId' => $CronId
]);
```


## getEnvironmentsDatabases

Returns a list of databases.
```php
$response = $client->getEnvironmentsDatabases([
	'EnvironmentId' => $EnvironmentId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postEnvironmentsDatabases

Copies a database to this environment.
```php
$response = $client->postEnvironmentsDatabases([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsDatabase

Return details about a specific database.
```php
$response = $client->getEnvironmentsDatabase([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName
]);
```


## getEnvironmentsDatabasePhpConfig

Returns PHP configuration details for this database.
```php
$response = $client->getEnvironmentsDatabasePhpConfig([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName
]);
```


## getEnvironmentsDatabaseBackups

Returns a list of backups.
```php
$response = $client->getEnvironmentsDatabaseBackups([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName,
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postEnvironmentsDatabaseBackups

Create a backup.
```php
$response = $client->postEnvironmentsDatabaseBackups([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName
]);
```


## getEnvironmentsDatabaseBackup

Return details about a specific backup.
```php
$response = $client->getEnvironmentsDatabaseBackup([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName,
	'BackupId' => $BackupId
]);
```


## deleteEnvironmentsDatabaseBackup

Deletes a database backup.
```php
$response = $client->deleteEnvironmentsDatabaseBackup([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName,
	'BackupId' => $BackupId
]);
```


## getEnvironmentsDatabaseDownloadBackup

Downloads the database backup file.
```php
$response = $client->getEnvironmentsDatabaseDownloadBackup([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName,
	'BackupId' => $BackupId
]);
```


## postEnvironmentsDatabaseRestoreBackup

Restores this backup to the appropriate environment's database.
```php
$response = $client->postEnvironmentsDatabaseRestoreBackup([
	'EnvironmentId' => $EnvironmentId,
	'DatabaseName' => $DatabaseName,
	'BackupId' => $BackupId
]);
```


## getEnvironmentsDns

Returns DNS configuration details for an environment.
```php
$response = $client->getEnvironmentsDns([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsDomains

Returns a list of domains.
```php
$response = $client->getEnvironmentsDomains([
	'EnvironmentId' => $EnvironmentId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postEnvironmentsDomains

Adds a domain to the environment.
```php
$response = $client->postEnvironmentsDomains([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentsDomainsClearVarnish

Clears the Varnish cache for one or more domains attached to this environment.
```php
$response = $client->postEnvironmentsDomainsClearVarnish([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsDomain

Return details about a specific domain.
```php
$response = $client->getEnvironmentsDomain([
	'EnvironmentId' => $EnvironmentId,
	'Domain' => $Domain
]);
```


## deleteEnvironmentsDomain

Removes the domain from this environment.
```php
$response = $client->deleteEnvironmentsDomain([
	'EnvironmentId' => $EnvironmentId,
	'Domain' => $Domain
]);
```


## postEnvironmentsDomainClearVarnish

Clears the Varnish cache for the specified domain.
```php
$response = $client->postEnvironmentsDomainClearVarnish([
	'EnvironmentId' => $EnvironmentId,
	'Domain' => $Domain
]);
```


## getEnvironmentsDomainsUptimeScans

Retrieves Uptime scan data for a specific domain.
```php
$response = $client->getEnvironmentsDomainsUptimeScans([
	'EnvironmentId' => $EnvironmentId,
	'Domain' => $Domain,
	'From' => $From,
	'To' => $To
]);
```


## getEnvironmentsDomainStatus

Returns details about the domain.
```php
$response = $client->getEnvironmentsDomainStatus([
	'EnvironmentId' => $EnvironmentId,
	'Domain' => $Domain
]);
```


## postEnvironmentsFiles

Copies files to this environment.
```php
$response = $client->postEnvironmentsFiles([
	'EnvironmentId' => $EnvironmentId
]);
```


## getInsightForEnvironment

Returns insight data.
```php
$response = $client->getInsightForEnvironment([
	'EnvironmentId' => $EnvironmentId,
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getEnvironmentsLogs

Returns a list of log files for this environment available for download.
```php
$response = $client->getEnvironmentsLogs([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsLog

Downloads the log file.
```php
$response = $client->getEnvironmentsLog([
	'EnvironmentId' => $EnvironmentId,
	'LogType' => $LogType
]);
```


## postEnvironmentsLog

Creates a log file snapshot.
```php
$response = $client->postEnvironmentsLog([
	'EnvironmentId' => $EnvironmentId,
	'LogType' => $LogType
]);
```


## getEnvironmentsLogstream

Returns a logstream url and metadata.
```php
$response = $client->getEnvironmentsLogstream([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentsDisableLiveDev

Disable Live Development on this environment.
```php
$response = $client->postEnvironmentsDisableLiveDev([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentsEnableLiveDev

Enable Live Development on this environment.
```php
$response = $client->postEnvironmentsEnableLiveDev([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsLogForwardingDestinations

Returns a collection of log forwarding destinations for this environment.
```php
$response = $client->getEnvironmentsLogForwardingDestinations([
	'EnvironmentId' => $EnvironmentId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postEnvironmentsLogForwardingDestinations

Creates a log forwarding destination.
```php
$response = $client->postEnvironmentsLogForwardingDestinations([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsLogForwardingDestination

Returns the specified log forwarding destination.
```php
$response = $client->getEnvironmentsLogForwardingDestination([
	'EnvironmentId' => $EnvironmentId,
	'LogForwardingDestinationUuid' => $LogForwardingDestinationUuid
]);
```


## putEnvironmentsLogForwardingDestination

Updates an environment's log forwarding destination.
```php
$response = $client->putEnvironmentsLogForwardingDestination([
	'EnvironmentId' => $EnvironmentId,
	'LogForwardingDestinationUuid' => $LogForwardingDestinationUuid
]);
```


## deleteEnvironmentsLogForwardingDestination

Deletes the specified log forwarding destination.
```php
$response = $client->deleteEnvironmentsLogForwardingDestination([
	'EnvironmentId' => $EnvironmentId,
	'LogForwardingDestinationUuid' => $LogForwardingDestinationUuid
]);
```


## postEnvironmentsDisableLogForwardingDestination

Disables the specified log forwarding destination.
```php
$response = $client->postEnvironmentsDisableLogForwardingDestination([
	'EnvironmentId' => $EnvironmentId,
	'LogForwardingDestinationUuid' => $LogForwardingDestinationUuid
]);
```


## postEnvironmentsEnableLogForwardingDestination

Enables the specified log forwarding destination.
```php
$response = $client->postEnvironmentsEnableLogForwardingDestination([
	'EnvironmentId' => $EnvironmentId,
	'LogForwardingDestinationUuid' => $LogForwardingDestinationUuid
]);
```


## getEnvironmentsMetrics

Does not return any data. Allows traversal to metrics groups endpoints.
```php
$response = $client->getEnvironmentsMetrics([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsStackMetrics

Does not return any data. Allows traversal to StackMetrics endpoints.
```php
$response = $client->getEnvironmentsStackMetrics([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsStackMetricsData

Returns StackMetrics data for the metrics specified in the filter paramater (e.g., apache-access, web-cpu).
```php
$response = $client->getEnvironmentsStackMetricsData([
	'EnvironmentId' => $EnvironmentId,
	'StackMetricsMetricTypes' => $StackMetricsMetricTypes
]);
```


## getEnvironmentsStackMetricsMetric

Returns StackMetrics data for the metric (e.g., apache-access).
```php
$response = $client->getEnvironmentsStackMetricsMetric([
	'EnvironmentId' => $EnvironmentId,
	'StackMetricsMetricType' => $StackMetricsMetricType,
	'ServerType' => $ServerType
]);
```


## getEnvironmentsUsageLinks

Retrieves traversal links for an environment's usage data.
```php
$response = $client->getEnvironmentsUsageLinks([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsUsageData

Retrieves usage data for an environment.
```php
$response = $client->getEnvironmentsUsageData([
	'EnvironmentId' => $EnvironmentId,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getEnvironmentsUsageMetricData

Retrieves usage metric data for an environment.
```php
$response = $client->getEnvironmentsUsageMetricData([
	'UsageMetric' => $UsageMetric,
	'EnvironmentId' => $EnvironmentId,
	'From' => $From,
	'To' => $To
]);
```


## postEnvironmentsDisableProductionMode

Disables production mode for an environment.
```php
$response = $client->postEnvironmentsDisableProductionMode([
	'EnvironmentId' => $EnvironmentId
]);
```


## postEnvironmentsEnableProductionMode

Enables production mode for an environment.
```php
$response = $client->postEnvironmentsEnableProductionMode([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsServers

Returns a list of servers.
```php
$response = $client->getEnvironmentsServers([
	'EnvironmentId' => $EnvironmentId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getEnvironmentsServer

Return details about a specific server.
```php
$response = $client->getEnvironmentsServer([
	'EnvironmentId' => $EnvironmentId,
	'ServerId' => $ServerId
]);
```


## putEnvironmentsServer

Modifies configuration settings for a server.
```php
$response = $client->putEnvironmentsServer([
	'EnvironmentId' => $EnvironmentId,
	'ServerId' => $ServerId
]);
```


## postEnvironmentsServerReboot

Reboots a server.
```php
$response = $client->postEnvironmentsServerReboot([
	'EnvironmentId' => $EnvironmentId,
	'ServerId' => $ServerId
]);
```


## postEnvironmentsServerRelaunch

Relaunches a server.
```php
$response = $client->postEnvironmentsServerRelaunch([
	'EnvironmentId' => $EnvironmentId,
	'ServerId' => $ServerId
]);
```


## postEnvironmentsServerSuspend

Suspends a server.
```php
$response = $client->postEnvironmentsServerSuspend([
	'EnvironmentId' => $EnvironmentId,
	'ServerId' => $ServerId
]);
```


## postEnvironmentsServerUpgrade

Upgrades a server from "precise" to "xenial".
```php
$response = $client->postEnvironmentsServerUpgrade([
	'EnvironmentId' => $EnvironmentId,
	'ServerId' => $ServerId
]);
```


## getEnvironmentsSettings

Provides links to environment settings.
```php
$response = $client->getEnvironmentsSettings([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsApmSetting

Return details about a specific APM.
```php
$response = $client->getEnvironmentsApmSetting([
	'EnvironmentId' => $EnvironmentId
]);
```


## putEnvironmentsApmSetting

Update configuration for an APM tool.
```php
$response = $client->putEnvironmentsApmSetting([
	'EnvironmentId' => $EnvironmentId
]);
```


## getSsl

Returns the SSL settings for this environment.
```php
$response = $client->getSsl([
	'EnvironmentId' => $EnvironmentId
]);
```


## getCertificates

Return a list of SSL certificates.
```php
$response = $client->getCertificates([
	'EnvironmentId' => $EnvironmentId
]);
```


## postCertificate

Install an SSL certificate.
```php
$response = $client->postCertificate([
	'EnvironmentId' => $EnvironmentId
]);
```


## getCertificate

Returns a specific certificate by certificate id.
```php
$response = $client->getCertificate([
	'EnvironmentId' => $EnvironmentId,
	'CertificateId' => $CertificateId
]);
```


## deleteCertificate

Deletes a specific certificate by its ID.
```php
$response = $client->deleteCertificate([
	'EnvironmentId' => $EnvironmentId,
	'CertificateId' => $CertificateId
]);
```


## postActivateCertificate

Activates an SSL certificate.
```php
$response = $client->postActivateCertificate([
	'EnvironmentId' => $EnvironmentId,
	'CertificateId' => $CertificateId
]);
```


## postDeactivateCertificate

Deactivates an active SSL certificate.
```php
$response = $client->postDeactivateCertificate([
	'EnvironmentId' => $EnvironmentId,
	'CertificateId' => $CertificateId
]);
```


## getCertificateSigningRequests

Returns certificate signing requests.
```php
$response = $client->getCertificateSigningRequests([
	'EnvironmentId' => $EnvironmentId
]);
```


## postCertificateSigningRequest

Generates a CSR for one or more domains.
```php
$response = $client->postCertificateSigningRequest([
	'EnvironmentId' => $EnvironmentId
]);
```


## getCertificateSigningRequest

Returns the certificate signing request for the certificate specified by id.
```php
$response = $client->getCertificateSigningRequest([
	'EnvironmentId' => $EnvironmentId,
	'CertificateId' => $CertificateId
]);
```


## deleteCertificateSigningRequest

Deletes the certificate signing request.
```php
$response = $client->deleteCertificateSigningRequest([
	'EnvironmentId' => $EnvironmentId,
	'CertificateId' => $CertificateId
]);
```


## getEnvironmentsVariables

Returns a list of environment variables associated with this environment.
```php
$response = $client->getEnvironmentsVariables([
	'EnvironmentId' => $EnvironmentId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postEnvironmentsVariables

Adds a new environment variable to an environment.
```php
$response = $client->postEnvironmentsVariables([
	'EnvironmentId' => $EnvironmentId
]);
```


## getEnvironmentsVariable

Get an environment variable associated with this environment.
```php
$response = $client->getEnvironmentsVariable([
	'EnvironmentId' => $EnvironmentId,
	'EnvironmentVariableName' => $EnvironmentVariableName
]);
```


## deleteEnvironmentsVariable

Removes an environment variable from an environment.
```php
$response = $client->deleteEnvironmentsVariable([
	'EnvironmentId' => $EnvironmentId,
	'EnvironmentVariableName' => $EnvironmentVariableName
]);
```


## putEnvironmentsVariable

Updates an environment variable on an environment.
```php
$response = $client->putEnvironmentsVariable([
	'EnvironmentId' => $EnvironmentId,
	'EnvironmentVariableName' => $EnvironmentVariableName
]);
```


## getIde

Returns Remote IDE info.
```php
$response = $client->getIde([
	'IdeUuid' => $IdeUuid
]);
```


## deleteIde

De-provisions a specific Remote IDE.
```php
$response = $client->deleteIde([
	'IdeUuid' => $IdeUuid
]);
```


## getIdentityProviders

Returns a list of identity providers for a user.
```php
$response = $client->getIdentityProviders([
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getIdentityProvider

Returns a specific identity provider by UUID.
```php
$response = $client->getIdentityProvider([
	'IdentityProviderUuid' => $IdentityProviderUuid
]);
```


## putIdentityProvider

Modifies an identity provider by its UUID.
```php
$response = $client->putIdentityProvider([
	'IdentityProviderUuid' => $IdentityProviderUuid
]);
```


## deleteIdentityProvider

Deletes a specific identity provider by its UUID.
```php
$response = $client->deleteIdentityProvider([
	'IdentityProviderUuid' => $IdentityProviderUuid
]);
```


## postEnableIdentityProvider

Enables an identity provider by its UUID.
```php
$response = $client->postEnableIdentityProvider([
	'IdentityProviderUuid' => $IdentityProviderUuid
]);
```


## postDisableIdentityProvider

Disables an identity provider by its UUID.
```php
$response = $client->postDisableIdentityProvider([
	'IdentityProviderUuid' => $IdentityProviderUuid
]);
```


## findInsightDataBySiteId

Returns insight data for a particular site.
```php
$response = $client->findInsightDataBySiteId([
	'SiteId' => $SiteId
]);
```


## postRevokeInsight

Revokes an Insight install so it can no longer submit data using the Acquia Connector module.
```php
$response = $client->postRevokeInsight([
	'SiteId' => $SiteId
]);
```


## postUnrevokeInsight

Un-revokes an Insight site so it can once again submit data using the Acquia Connector module. Note that the site must also be unblocked using the Acquia Connector module.
```php
$response = $client->postUnrevokeInsight([
	'SiteId' => $SiteId
]);
```


## getFindInsightAlertsForSite

Returns a list of Insight alerts for this site.
```php
$response = $client->getFindInsightAlertsForSite([
	'SiteId' => $SiteId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getInsightByUuid

Returns a specific Insight alert for this site.
```php
$response = $client->getInsightByUuid([
	'SiteId' => $SiteId,
	'AlertUuid' => $AlertUuid
]);
```


## postIgnoreInsightAlert

Ignores an alert. An ignored alert will not be counted in the Insight score calculation.
```php
$response = $client->postIgnoreInsightAlert([
	'SiteId' => $SiteId,
	'AlertUuid' => $AlertUuid
]);
```


## postRestoreInsightAlert

Restores an alert. A restored alert will be included in the calculation of the Insight score.
```php
$response = $client->postRestoreInsightAlert([
	'SiteId' => $SiteId,
	'AlertUuid' => $AlertUuid
]);
```


## getConnectionHistoryForSite

Returns a list of historical Insight connections for this site.
```php
$response = $client->getConnectionHistoryForSite([
	'SiteId' => $SiteId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getDrupalModulesForSite

Returns a list of Drupal modules for this site.
```php
$response = $client->getDrupalModulesForSite([
	'SiteId' => $SiteId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getScoreHistoryForSite

Returns a list of historical Insight scores for this site.
```php
$response = $client->getScoreHistoryForSite([
	'SiteId' => $SiteId,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset,
	'From' => $From,
	'To' => $To
]);
```


## getInviteByToken

Returns details about an invitation.
```php
$response = $client->getInviteByToken([
	'Token' => $Token
]);
```


## postInviteCancel

Cancels an invitation.
```php
$response = $client->postInviteCancel([
	'Token' => $Token
]);
```


## postInviteAcceptByToken

Accepts an invite.
```php
$response = $client->postInviteAcceptByToken([
	'Token' => $Token
]);
```


## postInviteDecline

Declines an invite.
```php
$response = $client->postInviteDecline([
	'Token' => $Token
]);
```


## postInviteResend

Resend an invite.
```php
$response = $client->postInviteResend([
	'Token' => $Token
]);
```


## postDismissMessage

Dismisses a message.
```php
$response = $client->postDismissMessage([
	'MessageUuid' => $MessageUuid
]);
```


## getMessageFollow

Follows an in-product message link.
```php
$response = $client->getMessageFollow([
	'MessageUuid' => $MessageUuid
]);
```


## getNotificationByUuid

Returns a single notification.
```php
$response = $client->getNotificationByUuid([
	'NotificationUuid' => $NotificationUuid
]);
```


## getOptions

Does not return any data. Allows traversal of options groups endpoints.
```php
$response = $client->getOptions();
```


## getCdeSizes

Displays the various CD Environment size options.
```php
$response = $client->getCdeSizes();
```


## getLogForwarding

Does not return any data. Allows traversal of options groups endpoints.
```php
$response = $client->getLogForwarding();
```


## getLogForwardingSources

Displays available log forwarding sources.
```php
$response = $client->getLogForwardingSources();
```


## getLogForwardingConsumers

Displays available log forwarding consumers.
```php
$response = $client->getLogForwardingConsumers();
```


## getColors

Displays the various color options.
```php
$response = $client->getColors();
```


## getOrganizations

Return a list of organizations.
```php
$response = $client->getOrganizations();
```


## postOrganizationsCreate

Creates a new organization.
```php
$response = $client->postOrganizationsCreate();
```


## getOrganizationByUuid

Return details about a specific organization.
```php
$response = $client->getOrganizationByUuid([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## putOrganization

Renames an organization.
```php
$response = $client->putOrganization([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## deleteOrganization

Deletes a specific organization by its UUID.
```php
$response = $client->deleteOrganization([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## postChangeOrganizationOwner

Changes the organization owner.
```php
$response = $client->postChangeOrganizationOwner([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## postLeaveOrganization

Removes your account from an organization.
```php
$response = $client->postLeaveOrganization([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## getOrganizationAdmins

Returns a list of organization administrators.
```php
$response = $client->getOrganizationAdmins([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getOrganizationAdmin

Returns the user profile of this organization administrator.
```php
$response = $client->getOrganizationAdmin([
	'OrganizationUuid' => $OrganizationUuid,
	'UserUuid' => $UserUuid
]);
```


## deleteOrganizationAdmin

Removes the user from the list of administrators for the organization.
```php
$response = $client->deleteOrganizationAdmin([
	'OrganizationUuid' => $OrganizationUuid,
	'UserUuid' => $UserUuid
]);
```


## getOrganizationAdminInvites

Gets a list of invitations of administrators for this organization.
```php
$response = $client->getOrganizationAdminInvites([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset,
	'Range' => $Range
]);
```


## postOrganizationAdminInvite

Invites a user to be an administrator in this organization.
```php
$response = $client->postOrganizationAdminInvite([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## getOrganizationApplications

Returns a list of applications that belong to the organization.
```php
$response = $client->getOrganizationApplications([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getOrganizationAvailableTags

Returns a list of all available application tags.
```php
$response = $client->getOrganizationAvailableTags([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## getOrganizationIdentityProvider

Returns an identity provider for an organization.
```php
$response = $client->getOrganizationIdentityProvider([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## getOrganizationMembers

Returns a list of all organization members.
```php
$response = $client->getOrganizationMembers([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit
]);
```


## getOrganizationMember

Returns the user profile of this organization member.
```php
$response = $client->getOrganizationMember([
	'OrganizationUuid' => $OrganizationUuid,
	'UserUuid' => $UserUuid
]);
```


## postOrganizationMemberDelete

Removes the member from the organization.
```php
$response = $client->postOrganizationMemberDelete([
	'OrganizationUuid' => $OrganizationUuid,
	'UserUuid' => $UserUuid
]);
```


## getOrganizationMemberApplications

Returns a list of applications that an organization member has access to.
```php
$response = $client->getOrganizationMemberApplications([
	'OrganizationUuid' => $OrganizationUuid,
	'UserUuid' => $UserUuid
]);
```


## getOrganizationRoles

Returns a list of all the canonical roles within the organization.
```php
$response = $client->getOrganizationRoles([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset,
	'Range' => $Range
]);
```


## postOrganizationRoles

Creates a role.
```php
$response = $client->postOrganizationRoles([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## getOrganizationSubscriptions

Returns a list of subscriptions that belong to the organization.
```php
$response = $client->getOrganizationSubscriptions([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset,
	'Range' => $Range
]);
```


## getOrganizationTeamInvites

Gets a list of member invitations for all teams in this organization.
```php
$response = $client->getOrganizationTeamInvites([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getOrganizationTeams

Returns a list of teams associated with the organization.
```php
$response = $client->getOrganizationTeams([
	'OrganizationUuid' => $OrganizationUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postOrganizationTeams

Creates a team.
```php
$response = $client->postOrganizationTeams([
	'OrganizationUuid' => $OrganizationUuid
]);
```


## getPermissions

Return a list of permissions.
```php
$response = $client->getPermissions();
```


## getRole

Return details about a specific role.
```php
$response = $client->getRole([
	'RoleUuid' => $RoleUuid
]);
```


## deleteRole

Deletes a specific role by its UUID.
```php
$response = $client->deleteRole([
	'RoleUuid' => $RoleUuid
]);
```


## putRoleByUuid

Updates a role.
```php
$response = $client->putRoleByUuid([
	'RoleUuid' => $RoleUuid
]);
```


## getSubscriptions

Return a list of subscription.
```php
$response = $client->getSubscriptions([
	'From' => $From,
	'To' => $To,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getSubscription

Return details about a specific subscription.
```php
$response = $client->getSubscription([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## putSubscription

Modifies a subscription.
```php
$response = $client->putSubscription([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## getSubscriptionApplications

Provides a list of applications that are a part of the subscription.
```php
$response = $client->getSubscriptionApplications([
	'SubscriptionUuid' => $SubscriptionUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## getSubscriptionEntitlements

Provides a list of entitlements that are a part of the subscription.
```php
$response = $client->getSubscriptionEntitlements([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## getSubscriptionIdes

Returns a list of Remote IDEs associated with this subscription.
```php
$response = $client->getSubscriptionIdes([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## getSubscriptionsUsageLinks

Retrieves traversal links for a subscription's usage data.
```php
$response = $client->getSubscriptionsUsageLinks([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## getSubscriptionsUsageData

Retrieves aggregate usage data for a subscription.
```php
$response = $client->getSubscriptionsUsageData([
	'SubscriptionUuid' => $SubscriptionUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getSubscriptionsUsageDataByApplication

Retrieves usage data for a subscription, broken down by application.
```php
$response = $client->getSubscriptionsUsageDataByApplication([
	'SubscriptionUuid' => $SubscriptionUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getSubscriptionsUsageMetricData

Retrieves aggregate usage metric data for a subscription.
```php
$response = $client->getSubscriptionsUsageMetricData([
	'UsageMetric' => $UsageMetric,
	'SubscriptionUuid' => $SubscriptionUuid,
	'From' => $From,
	'To' => $To
]);
```


## getSubscriptionsUsageViewsDataByApplication

Retrieves views data for a subscription, broken down by application.
```php
$response = $client->getSubscriptionsUsageViewsDataByApplication([
	'SubscriptionUuid' => $SubscriptionUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getSubscriptionsUsageVisitsDataByApplication

Retrieves visits data for a subscription, broken down by application.
```php
$response = $client->getSubscriptionsUsageVisitsDataByApplication([
	'SubscriptionUuid' => $SubscriptionUuid,
	'From' => $From,
	'To' => $To,
	'Filter' => $Filter,
	'Resolution' => $Resolution
]);
```


## getShieldAcl

Provides a list of Shield ACL rules.
```php
$response = $client->getShieldAcl([
	'SubscriptionUuid' => $SubscriptionUuid,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postShieldAcl

Creates a Shield ACL rule.
```php
$response = $client->postShieldAcl([
	'SubscriptionUuid' => $SubscriptionUuid
]);
```


## getShieldAclRuleByUuid

Returns the specified Shield ACL rule.
```php
$response = $client->getShieldAclRuleByUuid([
	'SubscriptionUuid' => $SubscriptionUuid,
	'ShieldAclUuid' => $ShieldAclUuid
]);
```


## putShieldAcl

Updates a Shield ACL rule.
```php
$response = $client->putShieldAcl([
	'SubscriptionUuid' => $SubscriptionUuid,
	'ShieldAclUuid' => $ShieldAclUuid
]);
```


## deleteShieldAcl

Deletes a Shield ACL rule.
```php
$response = $client->deleteShieldAcl([
	'SubscriptionUuid' => $SubscriptionUuid,
	'ShieldAclUuid' => $ShieldAclUuid
]);
```


## postResetShieldAcl

Resets Shield ACL rules to default settings.
```php
$response = $client->postResetShieldAcl([
	'SubscriptionUuid' => $SubscriptionUuid,
	'ShieldAclUuid' => $ShieldAclUuid
]);
```


## getTeams

Return teams the current user has access to.
```php
$response = $client->getTeams([
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset,
	'Range' => $Range
]);
```


## getTeam

Return details about a specific team.
```php
$response = $client->getTeam([
	'TeamUuid' => $TeamUuid
]);
```


## putTeamsName

Change the name of a team.
```php
$response = $client->putTeamsName([
	'TeamUuid' => $TeamUuid
]);
```


## deleteTeam

Deletes a specific team by its UUID.
```php
$response = $client->deleteTeam([
	'TeamUuid' => $TeamUuid
]);
```


## postLeaveTeam

Removes the current user from a team.
```php
$response = $client->postLeaveTeam([
	'TeamUuid' => $TeamUuid
]);
```


## getTeamApplications

Returns a list of applications this team has access to.
```php
$response = $client->getTeamApplications([
	'TeamUuid' => $TeamUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## postTeamAddApplication

Adds an application to this team.
```php
$response = $client->postTeamAddApplication([
	'TeamUuid' => $TeamUuid
]);
```


## deleteTeamsRemoveApplication

Removes the application from this team.
```php
$response = $client->deleteTeamsRemoveApplication([
	'TeamUuid' => $TeamUuid,
	'ApplicationUuid' => $ApplicationUuid
]);
```


## getTeamInvites

Returns a list of invitations to this team.
```php
$response = $client->getTeamInvites([
	'TeamUuid' => $TeamUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset,
	'Range' => $Range
]);
```


## postTeamsInviteUser

Invites a user to join a team.
```php
$response = $client->postTeamsInviteUser([
	'TeamUuid' => $TeamUuid
]);
```


## getTeamMembers

Returns a list of team members.
```php
$response = $client->getTeamMembers([
	'TeamUuid' => $TeamUuid,
	'Sort' => $Sort,
	'Filter' => $Filter,
	'Limit' => $Limit,
	'Offset' => $Offset
]);
```


## putTeamsMember

Grant team roles to a member.
```php
$response = $client->putTeamsMember([
	'TeamUuid' => $TeamUuid,
	'UserUuid' => $UserUuid
]);
```


## deleteTeamsRemoveMember

Remove a user from a team.
```php
$response = $client->deleteTeamsRemoveMember([
	'TeamUuid' => $TeamUuid,
	'UserUuid' => $UserUuid
]);
```


